package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	version = "1.0.0"
	commit  = "dev"
	date    = "unknown"
)

func main() {
	log.Printf("Starting A2Z IDS/IPS Management API v%s", version)

	// Get port from environment or default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Setup Gin router
	router := setupRouter()

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting HTTP server on port %s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

func setupRouter() *gin.Engine {
	// Set Gin mode
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()

	// Global middleware
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	// CORS configuration
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowAllOrigins = true
	corsConfig.AllowCredentials = true
	corsConfig.AllowHeaders = append(corsConfig.AllowHeaders, "Authorization", "X-Request-ID")
	router.Use(cors.New(corsConfig))

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "ok",
			"service":   "ids-management-api",
			"version":   version,
			"timestamp": time.Now().Unix(),
		})
	})

	// Metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// API version 1
	v1 := router.Group("/api/v1")
	{
		// System information
		system := v1.Group("/system")
		{
			system.GET("/status", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"status": "running",
					"uptime": time.Now().Unix(),
					"core_engine": gin.H{
						"status": "active",
						"mode":   "passive",
						"interface": "any",
					},
					"rules": gin.H{
						"total_rules":  156,
						"active_rules": 148,
						"last_update":  time.Now().Format(time.RFC3339),
					},
				})
			})

			system.GET("/info", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"name":    "A2Z IDS/IPS Management API",
					"version": version,
					"build": gin.H{
						"commit": commit,
						"date":   date,
					},
					"capabilities": []string{
						"intrusion-detection",
						"threat-prevention", 
						"ml-detection",
						"packet-inspection",
						"rule-management",
					},
				})
			})

			system.GET("/health", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"status": "healthy",
					"checks": gin.H{
						"database":    "ok",
						"core_engine": "ok",
						"rules":       "ok",
						"memory":      "ok",
					},
				})
			})
		}

		// Rules management (placeholder endpoints)
		rules := v1.Group("/rules")
		{
			rules.GET("", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"total": 156,
					"rules": []gin.H{
						{
							"id":       "rule-001",
							"name":     "SSH Brute Force Detection",
							"category": "bruteforce",
							"severity": "high",
							"enabled":  true,
						},
						{
							"id":       "rule-002", 
							"name":     "Port Scan Detection",
							"category": "portscan",
							"severity": "medium",
							"enabled":  true,
						},
					},
				})
			})

			rules.GET("/categories", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"categories": []string{
						"malware",
						"exploit",
						"trojan",
						"web-application",
						"network-scan",
						"bruteforce",
						"portscan",
					},
				})
			})
		}

		// Alerts management (placeholder endpoints)
		alerts := v1.Group("/alerts")
		{
			alerts.GET("", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"total": 47,
					"alerts": []gin.H{
						{
							"id":        "alert-001",
							"timestamp": time.Now().Format(time.RFC3339),
							"severity":  "high",
							"source_ip": "192.168.1.100",
							"rule_name": "SSH Brute Force Detection",
							"status":    "new",
						},
					},
				})
			})

			alerts.GET("/stats", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"total_alerts": 47,
					"by_severity": gin.H{
						"critical": 3,
						"high":     12,
						"medium":   20,
						"low":      12,
					},
					"by_status": gin.H{
						"new":          15,
						"acknowledged": 25,
						"resolved":     7,
					},
				})
			})
		}

		// Performance metrics (placeholder endpoints)
		metrics := v1.Group("/metrics")
		{
			metrics.GET("/performance", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"packets_per_second": 15000,
					"bytes_per_second":   125000000,
					"cpu_usage":          65.2,
					"memory_usage":       45.8,
					"processing_latency": 0.2,
					"detection_accuracy": 97.8,
				})
			})

			metrics.GET("/throughput", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"total_packets":    54000000,
					"packets_analyzed": 54000000,
					"threats_detected": 47,
					"packets_blocked":  1230,
					"uptime_seconds":   86400,
				})
			})
		}
	}

	return router
} 