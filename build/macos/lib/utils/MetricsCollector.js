const os = require('os');
const { EventEmitter } = require('events');

class MetricsCollector extends EventEmitter {
    constructor(options = {}) {
        super();
        this.options = {
            collectInterval: options.collectInterval || 30000, // 30 seconds
            retentionPeriod: options.retentionPeriod || 3600000, // 1 hour
            maxDataPoints: options.maxDataPoints || 120, // 120 data points
            ...options
        };
        
        this.metrics = new Map();
        this.counters = new Map();
        this.gauges = new Map();
        this.histograms = new Map();
        this.timers = new Map();
        
        this.isCollecting = false;
        this.collectionInterval = null;
        this.startTime = Date.now();
    }

    startCollection() {
        if (this.isCollecting) {
            return;
        }

        this.isCollecting = true;
        this.collectSystemMetrics();
        
        this.collectionInterval = setInterval(() => {
            this.collectSystemMetrics();
            this.cleanupOldMetrics();
        }, this.options.collectInterval);

        console.log('📊 Metrics collection started');
    }

    stopCollection() {
        if (!this.isCollecting) {
            return;
        }

        this.isCollecting = false;
        
        if (this.collectionInterval) {
            clearInterval(this.collectionInterval);
            this.collectionInterval = null;
        }

        console.log('📊 Metrics collection stopped');
    }

    // Counter operations
    incrementCounter(name, value = 1, labels = {}) {
        const key = this.buildMetricKey(name, labels);
        const current = this.counters.get(key) || 0;
        this.counters.set(key, current + value);
        
        this.recordTimeSeries(name, current + value, labels, 'counter');
    }

    getCounter(name, labels = {}) {
        const key = this.buildMetricKey(name, labels);
        return this.counters.get(key) || 0;
    }

    resetCounter(name, labels = {}) {
        const key = this.buildMetricKey(name, labels);
        this.counters.set(key, 0);
    }

    // Gauge operations
    setGauge(name, value, labels = {}) {
        const key = this.buildMetricKey(name, labels);
        this.gauges.set(key, value);
        
        this.recordTimeSeries(name, value, labels, 'gauge');
    }

    getGauge(name, labels = {}) {
        const key = this.buildMetricKey(name, labels);
        return this.gauges.get(key);
    }

    incrementGauge(name, value = 1, labels = {}) {
        const key = this.buildMetricKey(name, labels);
        const current = this.gauges.get(key) || 0;
        this.setGauge(name, current + value, labels);
    }

    decrementGauge(name, value = 1, labels = {}) {
        this.incrementGauge(name, -value, labels);
    }

    // Histogram operations
    recordHistogram(name, value, labels = {}) {
        const key = this.buildMetricKey(name, labels);
        
        if (!this.histograms.has(key)) {
            this.histograms.set(key, {
                values: [],
                count: 0,
                sum: 0,
                min: value,
                max: value
            });
        }

        const histogram = this.histograms.get(key);
        histogram.values.push({
            value: value,
            timestamp: Date.now()
        });
        histogram.count++;
        histogram.sum += value;
        histogram.min = Math.min(histogram.min, value);
        histogram.max = Math.max(histogram.max, value);

        // Keep only recent values
        const cutoffTime = Date.now() - this.options.retentionPeriod;
        histogram.values = histogram.values.filter(v => v.timestamp > cutoffTime);

        this.recordTimeSeries(name, value, labels, 'histogram');
    }

    getHistogram(name, labels = {}) {
        const key = this.buildMetricKey(name, labels);
        const histogram = this.histograms.get(key);
        
        if (!histogram || histogram.values.length === 0) {
            return null;
        }

        const values = histogram.values.map(v => v.value).sort((a, b) => a - b);
        
        return {
            count: histogram.count,
            sum: histogram.sum,
            min: histogram.min,
            max: histogram.max,
            mean: histogram.sum / histogram.count,
            median: this.calculatePercentile(values, 50),
            p95: this.calculatePercentile(values, 95),
            p99: this.calculatePercentile(values, 99)
        };
    }

    // Timer operations
    startTimer(name, labels = {}) {
        const key = this.buildMetricKey(name, labels);
        this.timers.set(key, Date.now());
        return key;
    }

    endTimer(timerKey) {
        const startTime = this.timers.get(timerKey);
        if (!startTime) {
            return null;
        }

        const duration = Date.now() - startTime;
        this.timers.delete(timerKey);
        
        // Parse back the name and labels from the key
        const { name, labels } = this.parseMetricKey(timerKey);
        this.recordHistogram(name, duration, labels);
        
        return duration;
    }

    time(name, labels = {}) {
        const startTime = Date.now();
        return () => {
            const duration = Date.now() - startTime;
            this.recordHistogram(name, duration, labels);
            return duration;
        };
    }

    // System metrics collection
    collectSystemMetrics() {
        const timestamp = Date.now();
        
        // CPU metrics
        const cpuUsage = process.cpuUsage();
        this.setGauge('system_cpu_user_seconds', cpuUsage.user / 1000000); // Convert to seconds
        this.setGauge('system_cpu_system_seconds', cpuUsage.system / 1000000);
        
        // Memory metrics
        const memUsage = process.memoryUsage();
        this.setGauge('system_memory_rss_bytes', memUsage.rss);
        this.setGauge('system_memory_heap_used_bytes', memUsage.heapUsed);
        this.setGauge('system_memory_heap_total_bytes', memUsage.heapTotal);
        this.setGauge('system_memory_external_bytes', memUsage.external);

        // System load (Unix-like systems)
        try {
            const loadAvg = os.loadavg();
            this.setGauge('system_load_1m', loadAvg[0]);
            this.setGauge('system_load_5m', loadAvg[1]);
            this.setGauge('system_load_15m', loadAvg[2]);
        } catch (error) {
            // Load average not available on Windows
        }

        // Process metrics
        this.setGauge('process_uptime_seconds', process.uptime());
        this.setGauge('agent_uptime_seconds', (timestamp - this.startTime) / 1000);

        // Event loop lag
        this.measureEventLoopLag();
    }

    measureEventLoopLag() {
        const start = process.hrtime.bigint();
        setImmediate(() => {
            const lag = Number(process.hrtime.bigint() - start) / 1000000; // Convert to milliseconds
            this.recordHistogram('system_event_loop_lag_ms', lag);
        });
    }

    // Time series data management
    recordTimeSeries(name, value, labels = {}, type = 'gauge') {
        const key = this.buildMetricKey(name, labels);
        const timestamp = Date.now();
        
        if (!this.metrics.has(key)) {
            this.metrics.set(key, {
                name: name,
                labels: labels,
                type: type,
                dataPoints: []
            });
        }

        const metric = this.metrics.get(key);
        metric.dataPoints.push({
            timestamp: timestamp,
            value: value
        });

        // Limit data points
        if (metric.dataPoints.length > this.options.maxDataPoints) {
            metric.dataPoints = metric.dataPoints.slice(-this.options.maxDataPoints);
        }
    }

    // Utility methods
    buildMetricKey(name, labels = {}) {
        const labelPairs = Object.entries(labels)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([key, value]) => `${key}="${value}"`)
            .join(',');
        
        return labelPairs ? `${name}{${labelPairs}}` : name;
    }

    parseMetricKey(key) {
        const match = key.match(/^([^{]+)(?:\{(.+)\})?$/);
        if (!match) {
            return { name: key, labels: {} };
        }

        const name = match[1];
        const labelsStr = match[2];
        const labels = {};

        if (labelsStr) {
            const labelPairs = labelsStr.split(',');
            labelPairs.forEach(pair => {
                const [key, value] = pair.split('=');
                if (key && value) {
                    labels[key] = value.replace(/"/g, '');
                }
            });
        }

        return { name, labels };
    }

    calculatePercentile(sortedValues, percentile) {
        if (sortedValues.length === 0) return 0;
        
        const index = (percentile / 100) * (sortedValues.length - 1);
        const lower = Math.floor(index);
        const upper = Math.ceil(index);
        
        if (lower === upper) {
            return sortedValues[lower];
        }
        
        const weight = index - lower;
        return sortedValues[lower] * (1 - weight) + sortedValues[upper] * weight;
    }

    cleanupOldMetrics() {
        const cutoffTime = Date.now() - this.options.retentionPeriod;
        
        for (const [key, metric] of this.metrics) {
            metric.dataPoints = metric.dataPoints.filter(
                point => point.timestamp > cutoffTime
            );
            
            if (metric.dataPoints.length === 0) {
                this.metrics.delete(key);
            }
        }
    }

    // Export methods
    getAllMetrics() {
        const result = {
            counters: Object.fromEntries(this.counters),
            gauges: Object.fromEntries(this.gauges),
            histograms: {},
            timeSeries: {}
        };

        // Add histogram summaries
        for (const [key, _] of this.histograms) {
            const { name, labels } = this.parseMetricKey(key);
            result.histograms[key] = this.getHistogram(name, labels);
        }

        // Add time series data
        for (const [key, metric] of this.metrics) {
            result.timeSeries[key] = {
                name: metric.name,
                labels: metric.labels,
                type: metric.type,
                dataPoints: metric.dataPoints
            };
        }

        return result;
    }

    getMetricsByName(name) {
        const result = {};
        
        for (const [key, metric] of this.metrics) {
            if (metric.name === name) {
                result[key] = metric;
            }
        }
        
        return result;
    }

    getMetricsByLabel(labelKey, labelValue) {
        const result = {};
        
        for (const [key, metric] of this.metrics) {
            if (metric.labels[labelKey] === labelValue) {
                result[key] = metric;
            }
        }
        
        return result;
    }

    // Prometheus-style export
    exportPrometheus() {
        let output = '';
        
        // Export counters
        for (const [key, value] of this.counters) {
            const { name, labels } = this.parseMetricKey(key);
            const labelStr = Object.entries(labels)
                .map(([k, v]) => `${k}="${v}"`)
                .join(',');
            
            output += `# TYPE ${name} counter\n`;
            output += `${name}${labelStr ? `{${labelStr}}` : ''} ${value}\n`;
        }

        // Export gauges
        for (const [key, value] of this.gauges) {
            const { name, labels } = this.parseMetricKey(key);
            const labelStr = Object.entries(labels)
                .map(([k, v]) => `${k}="${v}"`)
                .join(',');
            
            output += `# TYPE ${name} gauge\n`;
            output += `${name}${labelStr ? `{${labelStr}}` : ''} ${value}\n`;
        }

        return output;
    }

    // Statistics and reporting
    getSystemStats() {
        return {
            uptime: process.uptime(),
            memoryUsage: process.memoryUsage(),
            cpuUsage: process.cpuUsage(),
            platform: process.platform,
            nodeVersion: process.version,
            pid: process.pid
        };
    }

    getCollectionStats() {
        return {
            isCollecting: this.isCollecting,
            collectInterval: this.options.collectInterval,
            retentionPeriod: this.options.retentionPeriod,
            totalMetrics: this.metrics.size,
            totalCounters: this.counters.size,
            totalGauges: this.gauges.size,
            totalHistograms: this.histograms.size,
            activeTimers: this.timers.size
        };
    }

    reset() {
        this.counters.clear();
        this.gauges.clear();
        this.histograms.clear();
        this.timers.clear();
        this.metrics.clear();
        this.startTime = Date.now();
    }
}

module.exports = MetricsCollector; 