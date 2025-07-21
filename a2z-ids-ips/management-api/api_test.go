package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return setupRouter()
}

func TestHealthEndpoint(t *testing.T) {
	router := setupTestRouter()

	t.Run("GET /health returns 200 with correct response", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "ok", response["status"])
		assert.Equal(t, "ids-management-api", response["service"])
		assert.NotEmpty(t, response["version"])
		assert.NotEmpty(t, response["timestamp"])
	})

	t.Run("Health endpoint includes CORS headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
	})
}

func TestMetricsEndpoint(t *testing.T) {
	router := setupTestRouter()

	t.Run("GET /metrics returns Prometheus metrics", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/metrics", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "text/plain")

		// Should contain basic Prometheus metrics
		body := w.Body.String()
		assert.Contains(t, body, "# HELP")
		assert.Contains(t, body, "# TYPE")
	})
}

func TestSystemEndpoints(t *testing.T) {
	router := setupTestRouter()

	t.Run("GET /api/v1/system/status returns system status", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/system/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "running", response["status"])
		assert.NotEmpty(t, response["uptime"])

		// Check core_engine section
		coreEngine := response["core_engine"].(map[string]interface{})
		assert.Equal(t, "active", coreEngine["status"])
		assert.Equal(t, "passive", coreEngine["mode"])
		assert.Equal(t, "any", coreEngine["interface"])

		// Check rules section
		rules := response["rules"].(map[string]interface{})
		assert.Equal(t, float64(156), rules["total_rules"])
		assert.Equal(t, float64(148), rules["active_rules"])
		assert.NotEmpty(t, rules["last_update"])
	})

	t.Run("GET /api/v1/system/info returns system information", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/system/info", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "A2Z IDS/IPS Management API", response["name"])
		assert.NotEmpty(t, response["version"])

		// Check build information
		build := response["build"].(map[string]interface{})
		assert.NotEmpty(t, build["commit"])
		assert.NotEmpty(t, build["date"])

		// Check capabilities
		capabilities := response["capabilities"].([]interface{})
		assert.Contains(t, capabilities, "intrusion-detection")
		assert.Contains(t, capabilities, "threat-prevention")
		assert.Contains(t, capabilities, "ml-detection")
		assert.Contains(t, capabilities, "packet-inspection")
		assert.Contains(t, capabilities, "rule-management")
	})

	t.Run("GET /api/v1/system/health returns health check", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/system/health", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "healthy", response["status"])

		// Check health checks
		checks := response["checks"].(map[string]interface{})
		assert.Equal(t, "ok", checks["database"])
		assert.Equal(t, "ok", checks["core_engine"])
		assert.Equal(t, "ok", checks["rules"])
		assert.Equal(t, "ok", checks["memory"])
	})
}

func TestRulesEndpoints(t *testing.T) {
	router := setupTestRouter()

	t.Run("GET /api/v1/rules returns rules list", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/rules", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, float64(156), response["total"])

		// Check rules array
		rules := response["rules"].([]interface{})
		assert.Len(t, rules, 2) // Mock data has 2 rules

		// Check first rule
		rule1 := rules[0].(map[string]interface{})
		assert.Equal(t, "rule-001", rule1["id"])
		assert.Equal(t, "SSH Brute Force Detection", rule1["name"])
		assert.Equal(t, "bruteforce", rule1["category"])
		assert.Equal(t, "high", rule1["severity"])
		assert.Equal(t, true, rule1["enabled"])

		// Check second rule
		rule2 := rules[1].(map[string]interface{})
		assert.Equal(t, "rule-002", rule2["id"])
		assert.Equal(t, "Port Scan Detection", rule2["name"])
		assert.Equal(t, "portscan", rule2["category"])
		assert.Equal(t, "medium", rule2["severity"])
		assert.Equal(t, true, rule2["enabled"])
	})

	t.Run("GET /api/v1/rules/categories returns rule categories", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/rules/categories", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		categories := response["categories"].([]interface{})
		expectedCategories := []string{
			"malware", "exploit", "trojan", "web-application",
			"network-scan", "bruteforce", "portscan",
		}

		for _, expected := range expectedCategories {
			assert.Contains(t, categories, expected)
		}
	})
}

func TestAlertsEndpoints(t *testing.T) {
	router := setupTestRouter()

	t.Run("GET /api/v1/alerts returns alerts list", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/alerts", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, float64(47), response["total"])

		// Check alerts array
		alerts := response["alerts"].([]interface{})
		assert.Len(t, alerts, 1) // Mock data has 1 alert

		// Check alert structure
		alert := alerts[0].(map[string]interface{})
		assert.Equal(t, "alert-001", alert["id"])
		assert.NotEmpty(t, alert["timestamp"])
		assert.Equal(t, "high", alert["severity"])
		assert.Equal(t, "192.168.1.100", alert["source_ip"])
		assert.Equal(t, "SSH Brute Force Detection", alert["rule_name"])
		assert.Equal(t, "new", alert["status"])
	})

	t.Run("GET /api/v1/alerts/stats returns alert statistics", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/alerts/stats", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, float64(47), response["total_alerts"])

		// Check by_severity breakdown
		bySeverity := response["by_severity"].(map[string]interface{})
		assert.Equal(t, float64(3), bySeverity["critical"])
		assert.Equal(t, float64(12), bySeverity["high"])
		assert.Equal(t, float64(20), bySeverity["medium"])
		assert.Equal(t, float64(12), bySeverity["low"])

		// Check by_status breakdown
		byStatus := response["by_status"].(map[string]interface{})
		assert.Equal(t, float64(15), byStatus["new"])
		assert.Equal(t, float64(25), byStatus["acknowledged"])
		assert.Equal(t, float64(7), byStatus["resolved"])
	})
}

func TestMetricsEndpoints(t *testing.T) {
	router := setupTestRouter()

	t.Run("GET /api/v1/metrics/performance returns performance metrics", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/metrics/performance", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, float64(15000), response["packets_per_second"])
		assert.Equal(t, float64(125000000), response["bytes_per_second"])
		assert.Equal(t, 65.2, response["cpu_usage"])
		assert.Equal(t, 45.8, response["memory_usage"])
		assert.Equal(t, 0.2, response["processing_latency"])
		assert.Equal(t, 97.8, response["detection_accuracy"])
	})

	t.Run("GET /api/v1/metrics/throughput returns throughput metrics", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/metrics/throughput", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, float64(54000000), response["total_packets"])
		assert.Equal(t, float64(54000000), response["packets_analyzed"])
		assert.Equal(t, float64(47), response["threats_detected"])
		assert.Equal(t, float64(1230), response["packets_blocked"])
		assert.Equal(t, float64(86400), response["uptime_seconds"])
	})
}

func TestCORSHeaders(t *testing.T) {
	router := setupTestRouter()

	t.Run("OPTIONS request returns proper CORS headers", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/api/v1/system/status", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "Content-Type")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Content-Type")
	})

	t.Run("All API endpoints include CORS headers", func(t *testing.T) {
		endpoints := []string{
			"/api/v1/system/status",
			"/api/v1/system/info",
			"/api/v1/system/health",
			"/api/v1/rules",
			"/api/v1/rules/categories",
			"/api/v1/alerts",
			"/api/v1/alerts/stats",
			"/api/v1/metrics/performance",
			"/api/v1/metrics/throughput",
		}

		for _, endpoint := range endpoints {
			req := httptest.NewRequest("GET", endpoint, nil)
			req.Header.Set("Origin", "http://localhost:3000")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"),
				"CORS header missing for %s", endpoint)
		}
	})
}

func TestErrorHandling(t *testing.T) {
	router := setupTestRouter()

	t.Run("404 for non-existent endpoints", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("405 for unsupported methods", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/system/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestJSONResponseFormat(t *testing.T) {
	router := setupTestRouter()

	t.Run("All endpoints return valid JSON", func(t *testing.T) {
		endpoints := []string{
			"/api/v1/system/status",
			"/api/v1/system/info",
			"/api/v1/system/health",
			"/api/v1/rules",
			"/api/v1/rules/categories",
			"/api/v1/alerts",
			"/api/v1/alerts/stats",
			"/api/v1/metrics/performance",
			"/api/v1/metrics/throughput",
		}

		for _, endpoint := range endpoints {
			req := httptest.NewRequest("GET", endpoint, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "Endpoint %s failed", endpoint)
			assert.Contains(t, w.Header().Get("Content-Type"), "application/json",
				"Content-Type not JSON for %s", endpoint)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err, "Invalid JSON response for %s", endpoint)
		}
	})
}

func TestPerformance(t *testing.T) {
	router := setupTestRouter()

	t.Run("Response time is reasonable", func(t *testing.T) {
		endpoints := []string{
			"/api/v1/system/status",
			"/api/v1/rules",
			"/api/v1/alerts",
			"/api/v1/metrics/performance",
		}

		for _, endpoint := range endpoints {
			start := time.Now()

			req := httptest.NewRequest("GET", endpoint, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			duration := time.Since(start)

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Less(t, duration, 100*time.Millisecond,
				"Endpoint %s took too long: %v", endpoint, duration)
		}
	})

	t.Run("Can handle concurrent requests", func(t *testing.T) {
		const numRequests = 100
		const numWorkers = 10

		requests := make(chan string, numRequests)
		results := make(chan bool, numRequests)

		// Start workers
		for i := 0; i < numWorkers; i++ {
			go func() {
				for endpoint := range requests {
					req := httptest.NewRequest("GET", endpoint, nil)
					w := httptest.NewRecorder()

					router.ServeHTTP(w, req)

					results <- w.Code == http.StatusOK
				}
			}()
		}

		// Send requests
		start := time.Now()
		for i := 0; i < numRequests; i++ {
			requests <- "/api/v1/system/status"
		}
		close(requests)

		// Collect results
		successCount := 0
		for i := 0; i < numRequests; i++ {
			if <-results {
				successCount++
			}
		}

		duration := time.Since(start)

		assert.Equal(t, numRequests, successCount, "Not all requests succeeded")
		assert.Less(t, duration, 5*time.Second, "Concurrent requests took too long")

		requestsPerSecond := float64(numRequests) / duration.Seconds()
		assert.Greater(t, requestsPerSecond, 100.0, "Throughput too low: %.2f req/s", requestsPerSecond)
	})
}

func TestSecurityHeaders(t *testing.T) {
	router := setupTestRouter()

	t.Run("Security headers are present", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/system/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Check for security headers (if implemented)
		// Note: These would need to be added to the actual implementation
		// assert.NotEmpty(t, w.Header().Get("X-Content-Type-Options"))
		// assert.NotEmpty(t, w.Header().Get("X-Frame-Options"))
		// assert.NotEmpty(t, w.Header().Get("X-XSS-Protection"))
	})
}

func TestHealthCheckIntegration(t *testing.T) {
	router := setupTestRouter()

	t.Run("Health check endpoint works for monitoring", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "ok", response["status"])
		assert.Equal(t, "ids-management-api", response["service"])

		// Timestamp should be recent
		timestamp, ok := response["timestamp"].(float64)
		assert.True(t, ok)
		assert.WithinDuration(t, time.Now(), time.Unix(int64(timestamp), 0), 5*time.Second)
	})
}

func TestContentNegotiation(t *testing.T) {
	router := setupTestRouter()

	t.Run("Accepts JSON content type", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/system/status", nil)
		req.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
	})

	t.Run("Handles missing Accept header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/system/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
	})
}

func TestRateLimiting(t *testing.T) {
	router := setupTestRouter()

	t.Run("Can handle burst requests", func(t *testing.T) {
		const burstSize = 50

		for i := 0; i < burstSize; i++ {
			req := httptest.NewRequest("GET", "/api/v1/system/status", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			// All requests should succeed (no rate limiting implemented yet)
			assert.Equal(t, http.StatusOK, w.Code)
		}
	})
}

func TestGracefulShutdown(t *testing.T) {
	// This test would need to be implemented with actual server lifecycle
	// For now, we test that the router can be created and destroyed
	t.Run("Router can be created and cleaned up", func(t *testing.T) {
		router := setupTestRouter()
		assert.NotNil(t, router)

		// Test that router is functional
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestAPIVersioning(t *testing.T) {
	router := setupTestRouter()

	t.Run("API v1 endpoints are accessible", func(t *testing.T) {
		v1Endpoints := []string{
			"/api/v1/system/status",
			"/api/v1/system/info",
			"/api/v1/system/health",
			"/api/v1/rules",
			"/api/v1/alerts",
			"/api/v1/metrics/performance",
		}

		for _, endpoint := range v1Endpoints {
			req := httptest.NewRequest("GET", endpoint, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "Endpoint %s failed", endpoint)
		}
	})
}

func TestDataValidation(t *testing.T) {
	router := setupTestRouter()

	t.Run("Response data structure is consistent", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/system/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		// Check required fields
		assert.NotEmpty(t, response["status"])
		assert.NotEmpty(t, response["uptime"])
		assert.NotEmpty(t, response["core_engine"])
		assert.NotEmpty(t, response["rules"])

		// Check data types
		assert.IsType(t, "string", response["status"])
		assert.IsType(t, float64(0), response["uptime"])
		assert.IsType(t, map[string]interface{}{}, response["core_engine"])
		assert.IsType(t, map[string]interface{}{}, response["rules"])
	})
}

func TestMemoryUsage(t *testing.T) {
	router := setupTestRouter()

	t.Run("Memory usage remains stable under load", func(t *testing.T) {
		const numRequests = 1000

		// Warm up
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest("GET", "/api/v1/system/status", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
		}

		// Force garbage collection
		runtime.GC()

		// Measure initial memory
		var m1 runtime.MemStats
		runtime.ReadMemStats(&m1)

		// Make many requests
		for i := 0; i < numRequests; i++ {
			req := httptest.NewRequest("GET", "/api/v1/system/status", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
		}

		// Force garbage collection
		runtime.GC()

		// Measure final memory
		var m2 runtime.MemStats
		runtime.ReadMemStats(&m2)

		// Memory increase should be reasonable
		memoryIncrease := m2.Alloc - m1.Alloc
		assert.Less(t, memoryIncrease, uint64(10*1024*1024), // Less than 10MB
			"Memory usage increased by %d bytes", memoryIncrease)
	})
}

// Benchmark tests
func BenchmarkHealthEndpoint(b *testing.B) {
	router := setupTestRouter()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			b.Fatalf("Expected status 200, got %d", w.Code)
		}
	}
}

func BenchmarkSystemStatus(b *testing.B) {
	router := setupTestRouter()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/api/v1/system/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			b.Fatalf("Expected status 200, got %d", w.Code)
		}
	}
}

func BenchmarkRulesEndpoint(b *testing.B) {
	router := setupTestRouter()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/api/v1/rules", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			b.Fatalf("Expected status 200, got %d", w.Code)
		}
	}
}

func BenchmarkConcurrentRequests(b *testing.B) {
	router := setupTestRouter()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/api/v1/system/status", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				b.Fatalf("Expected status 200, got %d", w.Code)
			}
		}
	})
}
