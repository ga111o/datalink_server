package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	UploadDir              = "/data/uploads"
	DefaultMaxFileSizeMB   = 5000 // 5GB
	IDLength               = 8
	MetadataFile           = "/data/uploads/.metadata.json"
	DefaultExpirationHours = 24
	DefaultCleanupHours    = 1
)

var (
	MaxFileSize     int64
	ExpirationTime  time.Duration
	CleanupInterval time.Duration
)

type FileMetadata struct {
	ID           string    `json:"id"`
	OriginalName string    `json:"original_name"`
	StoredName   string    `json:"stored_name"`
	UploadTime   time.Time `json:"upload_time"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type FileManager struct {
	mu          sync.RWMutex
	idToFile    map[string]string
	metadata    map[string]*FileMetadata
	usedIDs     map[string]bool
	cleanupStop chan bool
}

type Server struct {
	fileManager *FileManager
}

type UploadResponse struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func initConfig() {
	maxFileSizeMB := DefaultMaxFileSizeMB
	if envMaxSize := os.Getenv("MAX_FILE_SIZE_MB"); envMaxSize != "" {
		if parsedSize, err := strconv.Atoi(envMaxSize); err == nil && parsedSize > 0 {
			maxFileSizeMB = parsedSize
		} else {
			log.Printf("Invalid MAX_FILE_SIZE_MB value: %s, using default: %d", envMaxSize, DefaultMaxFileSizeMB)
		}
	}
	MaxFileSize = int64(maxFileSizeMB) * 1024 * 1024

	expirationHours := DefaultExpirationHours
	if envExpHours := os.Getenv("FILE_EXPIRATION_HOURS"); envExpHours != "" {
		if parsedHours, err := strconv.Atoi(envExpHours); err == nil && parsedHours > 0 {
			expirationHours = parsedHours
		} else {
			log.Printf("Invalid FILE_EXPIRATION_HOURS value: %s, using default: %d", envExpHours, DefaultExpirationHours)
		}
	}
	ExpirationTime = time.Duration(expirationHours) * time.Hour

	cleanupHours := DefaultCleanupHours
	if envCleanupHours := os.Getenv("CLEANUP_INTERVAL_HOURS"); envCleanupHours != "" {
		if parsedHours, err := strconv.Atoi(envCleanupHours); err == nil && parsedHours > 0 {
			cleanupHours = parsedHours
		} else {
			log.Printf("Invalid CLEANUP_INTERVAL_HOURS value: %s, using default: %d", envCleanupHours, DefaultCleanupHours)
		}
	}
	CleanupInterval = time.Duration(cleanupHours) * time.Hour

	log.Printf("Configuration initialized: MaxFileSize=%d MB, ExpirationTime=%s, CleanupInterval=%s",
		MaxFileSize/(1024*1024), ExpirationTime, CleanupInterval)
}

func NewFileManager() *FileManager {
	fm := &FileManager{
		idToFile:    make(map[string]string),
		metadata:    make(map[string]*FileMetadata),
		usedIDs:     make(map[string]bool),
		cleanupStop: make(chan bool),
	}

	fm.loadMetadata()
	fm.recoverFromFilesystem()
	fm.startCleanupRoutine()

	return fm
}

func NewServer() *Server {
	return &Server{
		fileManager: NewFileManager(),
	}
}

func (fm *FileManager) loadMetadata() {
	data, err := os.ReadFile(MetadataFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Error reading metadata file: %v", err)
		}
		return
	}

	var metadataList []*FileMetadata
	if err := json.Unmarshal(data, &metadataList); err != nil {
		log.Printf("Error parsing metadata file: %v", err)
		return
	}

	fm.mu.Lock()
	defer fm.mu.Unlock()

	for _, meta := range metadataList {
		fm.metadata[meta.ID] = meta
		fm.idToFile[meta.ID] = meta.StoredName
		fm.usedIDs[meta.ID] = true

		filePath := filepath.Join(UploadDir, meta.StoredName)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			delete(fm.metadata, meta.ID)
			delete(fm.idToFile, meta.ID)
			delete(fm.usedIDs, meta.ID)
		}
	}

	log.Printf("Loaded metadata for %d files", len(fm.metadata))
}

func (fm *FileManager) saveMetadata() error {
	fm.mu.RLock()
	var metadataList []*FileMetadata
	for _, meta := range fm.metadata {
		metadataList = append(metadataList, meta)
	}
	fm.mu.RUnlock()

	data, err := json.MarshalIndent(metadataList, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(MetadataFile, data, 0644)
}

func (fm *FileManager) recoverFromFilesystem() {
	files, err := os.ReadDir(UploadDir)
	if err != nil {
		log.Printf("Error reading upload directory: %v", err)
		return
	}

	pattern := regexp.MustCompile(`^(\d{8})_(\d{8}_\d{6})_(.+\.tar\.gz)$`)

	recovered := 0
	func() {
		fm.mu.Lock()
		defer fm.mu.Unlock()

		for _, file := range files {
			if file.IsDir() || strings.HasPrefix(file.Name(), ".") {
				continue
			}

			matches := pattern.FindStringSubmatch(file.Name())
			if len(matches) != 4 {
				log.Printf("Skipping file with unexpected format: %s", file.Name())
				continue
			}

			id := matches[1]
			timestampStr := matches[2]
			originalName := matches[3]

			if _, exists := fm.metadata[id]; exists {
				continue
			}

			uploadTime, err := time.Parse("20060102_150405", timestampStr)
			if err != nil {
				log.Printf("Error parsing timestamp for file %s: %v", file.Name(), err)
				continue
			}

			meta := &FileMetadata{
				ID:           id,
				OriginalName: originalName,
				StoredName:   file.Name(),
				UploadTime:   uploadTime,
				ExpiresAt:    uploadTime.Add(ExpirationTime),
			}

			fm.metadata[id] = meta
			fm.idToFile[id] = file.Name()
			fm.usedIDs[id] = true
			recovered++
		}
	}()

	if recovered > 0 {
		log.Printf("Recovered metadata for %d files from filesystem", recovered)
		if err := fm.saveMetadata(); err != nil {
			log.Printf("Error saving metadata after recovery: %v", err)
		}
	}
}

func (fm *FileManager) startCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(CleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				fm.cleanupExpiredFiles()
			case <-fm.cleanupStop:
				return
			}
		}
	}()
}

func (fm *FileManager) cleanupExpiredFiles() {
	now := time.Now()
	var toDelete []string

	fm.mu.RLock()
	for id, meta := range fm.metadata {
		if now.After(meta.ExpiresAt) {
			toDelete = append(toDelete, id)
		}
	}
	fm.mu.RUnlock()

	if len(toDelete) == 0 {
		return
	}

	fm.mu.Lock()
	defer fm.mu.Unlock()

	for _, id := range toDelete {
		meta := fm.metadata[id]
		filePath := filepath.Join(UploadDir, meta.StoredName)

		if err := os.Remove(filePath); err != nil {
			log.Printf("Error deleting expired file %s: %v", filePath, err)
			continue
		}

		delete(fm.metadata, id)
		delete(fm.idToFile, id)
		delete(fm.usedIDs, id)

		log.Printf("Deleted expired file: ID=%s, file=%s", id, meta.StoredName)
	}

	if err := fm.saveMetadata(); err != nil {
		log.Printf("Error saving metadata after cleanup: %v", err)
	}

	log.Printf("Cleanup completed: removed %d expired files", len(toDelete))
}

func (fm *FileManager) stopCleanup() {
	close(fm.cleanupStop)
}

func (fm *FileManager) generateUniqueID() (string, error) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	maxAttempts := 1000
	for attempts := 0; attempts < maxAttempts; attempts++ {
		min := int64(10000000) // 8자리 min // 0부터시작해도문제없으?려나
		max := int64(99999999) // max

		n, err := rand.Int(rand.Reader, big.NewInt(max-min+1))
		if err != nil {
			return "", err
		}

		id := fmt.Sprintf("%08d", n.Int64()+min)

		if !fm.usedIDs[id] {
			return id, nil
		}
	}

	return "", fmt.Errorf("failed to generate unique ID after %d attempts", maxAttempts)
}

func (fm *FileManager) addFile(id, originalName, storedName string) {
	now := time.Now()
	meta := &FileMetadata{
		ID:           id,
		OriginalName: originalName,
		StoredName:   storedName,
		UploadTime:   now,
		ExpiresAt:    now.Add(ExpirationTime),
	}

	fm.mu.Lock()
	fm.metadata[id] = meta
	fm.idToFile[id] = storedName
	fm.usedIDs[id] = true
	fm.mu.Unlock()

	go func() {
		if err := fm.saveMetadata(); err != nil {
			log.Printf("Error saving metadata: %v", err)
		}
	}()
}

func validateTarGz(file io.Reader) error {
	limitedReader := io.LimitReader(file, 1024*1024)

	gzReader, err := gzip.NewReader(limitedReader)
	if err != nil {
		return fmt.Errorf("invalid gzip format: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	_, err = tarReader.Next()
	if err != nil && err != io.EOF {
		return fmt.Errorf("invalid tar format: %w", err)
	}

	return nil
}

func ensureUploadDir() error {
	return os.MkdirAll(UploadDir, 0755)
}

func extractOriginalFilename(storedFilename string) string {
	parts := strings.Split(storedFilename, "_")
	if len(parts) >= 3 {
		return strings.Join(parts[2:], "_")
	}
	return storedFilename
}

func (s *Server) uploadHandler(c *gin.Context) {
	contentType := c.GetHeader("Content-Type")
	if !strings.Contains(contentType, "multipart/form-data") &&
		!strings.Contains(contentType, "application/gzip") &&
		!strings.Contains(contentType, "application/x-gzip") {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Content-Type must be multipart/form-data or application/gzip",
		})
		return
	}

	var file io.Reader
	var filename string
	var fileSize int64

	if strings.Contains(contentType, "multipart/form-data") {
		formFile, header, err := c.Request.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "Failed to get file from form: " + err.Error(),
			})
			return
		}
		defer formFile.Close()

		file = formFile
		filename = header.Filename
		fileSize = header.Size
	} else {
		file = c.Request.Body
		filename = "upload.tar.gz"
		fileSize = c.Request.ContentLength
	}

	if fileSize > MaxFileSize {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("File size exceeds maximum allowed size of %d bytes", MaxFileSize),
		})
		return
	}

	if !strings.HasSuffix(strings.ToLower(filename), ".tar.gz") {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "File must have .tar.gz extension",
		})
		return
	}

	fileContent, err := io.ReadAll(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to read file content: " + err.Error(),
		})
		return
	}

	if err := validateTarGz(strings.NewReader(string(fileContent))); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid tar.gz file: " + err.Error(),
		})
		return
	}

	id, err := s.fileManager.generateUniqueID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to generate unique ID: " + err.Error(),
		})
		return
	}

	timestamp := time.Now().Format("20060102_150405")
	savedFilename := fmt.Sprintf("%s_%s_%s", id, timestamp, filename)
	filePath := filepath.Join(UploadDir, savedFilename)

	if err := os.WriteFile(filePath, fileContent, 0644); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to save file: " + err.Error(),
		})
		return
	}

	s.fileManager.addFile(id, filename, savedFilename)

	log.Printf("File uploaded successfully: ID=%s, filename=%s, size=%d bytes, expires=%s",
		id, filename, len(fileContent), time.Now().Add(ExpirationTime).Format(time.RFC3339))

	c.JSON(http.StatusOK, UploadResponse{
		ID:      id,
		Message: "File uploaded successfully",
	})
}

func (s *Server) downloadHandler(c *gin.Context) {
	id := c.Param("id")

	if len(id) != IDLength {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid ID format. ID must be 8 digits",
		})
		return
	}

	s.fileManager.mu.RLock()
	meta, exists := s.fileManager.metadata[id]
	s.fileManager.mu.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error: "File not found",
		})
		return
	}

	if time.Now().After(meta.ExpiresAt) {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error: "File has expired",
		})
		return
	}

	filePath := filepath.Join(UploadDir, meta.StoredName)

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		s.fileManager.mu.Lock()
		delete(s.fileManager.metadata, id)
		delete(s.fileManager.idToFile, id)
		delete(s.fileManager.usedIDs, id)
		s.fileManager.mu.Unlock()

		c.JSON(http.StatusNotFound, ErrorResponse{
			Error: "File not found on disk",
		})
		return
	}

	log.Printf("File download requested: ID=%s, original=%s, expires=%s",
		id, meta.OriginalName, meta.ExpiresAt.Format(time.RFC3339))

	c.Header("Content-Type", "application/gzip")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", meta.OriginalName))

	c.File(filePath)
}

func (s *Server) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "datalink_server",
		"time":    time.Now().Format(time.RFC3339),
	})
}

func (s *Server) statusHandler(c *gin.Context) {
	s.fileManager.mu.RLock()
	fileCount := len(s.fileManager.metadata)

	now := time.Now()
	expiringSoon := 0
	for _, meta := range s.fileManager.metadata {
		if meta.ExpiresAt.Sub(now) < time.Hour {
			expiringSoon++
		}
	}
	s.fileManager.mu.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"files_stored":     fileCount,
		"expiring_soon":    expiringSoon,
		"upload_dir":       UploadDir,
		"max_file_size":    MaxFileSize,
		"expiration_time":  ExpirationTime.String(),
		"cleanup_interval": CleanupInterval.String(),
	})
}

func setupRouter(server *Server) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	r.MaxMultipartMemory = MaxFileSize

	r.POST("/upload", server.uploadHandler)
	r.GET("/download/:id", server.downloadHandler)
	r.GET("/health", server.healthHandler)
	r.GET("/status", server.statusHandler)

	return r
}

func main() {
	initConfig()

	if err := ensureUploadDir(); err != nil {
		log.Fatalf("Failed to create upload directory: %v", err)
	}

	server := NewServer()

	router := setupRouter(server)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting datalink server on port %s", port)
	log.Printf("Upload directory: %s", UploadDir)
	log.Printf("Max file size: %d bytes (%.2f MB)", MaxFileSize, float64(MaxFileSize)/(1024*1024))
	log.Printf("File expiration: %s", ExpirationTime.String())
	log.Printf("Cleanup interval: %s", CleanupInterval.String())

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	log.Printf("Server started successfully on port %s", port)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server.fileManager.stopCleanup()

	if err := server.fileManager.saveMetadata(); err != nil {
		log.Printf("Error saving metadata on shutdown: %v", err)
	} else {
		log.Println("Metadata saved successfully")
	}

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	} else {
		log.Println("Server shutdown completed gracefully")
	}
}
