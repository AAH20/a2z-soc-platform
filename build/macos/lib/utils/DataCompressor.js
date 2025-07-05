const zlib = require('zlib');
const { promisify } = require('util');

class DataCompressor {
    constructor(options = {}) {
        this.options = {
            level: options.level || 6, // Compression level (1-9)
            algorithm: options.algorithm || 'gzip', // gzip, deflate, brotli
            chunkSize: options.chunkSize || 16 * 1024, // 16KB chunks
            threshold: options.threshold || 1024, // Only compress if larger than 1KB
            ...options
        };
        
        // Promisify compression functions
        this.gzipAsync = promisify(zlib.gzip);
        this.gunzipAsync = promisify(zlib.gunzip);
        this.deflateAsync = promisify(zlib.deflate);
        this.inflateAsync = promisify(zlib.inflate);
        this.brotliCompressAsync = promisify(zlib.brotliCompress);
        this.brotliDecompressAsync = promisify(zlib.brotliDecompress);
        
        this.stats = {
            totalCompressions: 0,
            totalBytes: 0,
            compressedBytes: 0,
            totalTime: 0
        };
    }

    async compress(data) {
        const startTime = process.hrtime.bigint();
        
        try {
            // Convert data to buffer if needed
            let inputBuffer;
            if (Buffer.isBuffer(data)) {
                inputBuffer = data;
            } else if (typeof data === 'string') {
                inputBuffer = Buffer.from(data, 'utf8');
            } else {
                inputBuffer = Buffer.from(JSON.stringify(data), 'utf8');
            }

            // Check if compression is worth it
            if (inputBuffer.length < this.options.threshold) {
                return {
                    compressed: false,
                    data: inputBuffer,
                    originalSize: inputBuffer.length,
                    compressedSize: inputBuffer.length,
                    compressionRatio: 1,
                    algorithm: 'none'
                };
            }

            // Compress based on algorithm
            let compressedBuffer;
            let algorithm = this.options.algorithm;

            switch (algorithm) {
                case 'gzip':
                    compressedBuffer = await this.gzipAsync(inputBuffer, {
                        level: this.options.level,
                        chunkSize: this.options.chunkSize
                    });
                    break;
                    
                case 'deflate':
                    compressedBuffer = await this.deflateAsync(inputBuffer, {
                        level: this.options.level,
                        chunkSize: this.options.chunkSize
                    });
                    break;
                    
                case 'brotli':
                    compressedBuffer = await this.brotliCompressAsync(inputBuffer, {
                        params: {
                            [zlib.constants.BROTLI_PARAM_QUALITY]: this.options.level,
                            [zlib.constants.BROTLI_PARAM_SIZE_HINT]: inputBuffer.length
                        }
                    });
                    break;
                    
                default:
                    throw new Error(`Unsupported compression algorithm: ${algorithm}`);
            }

            const endTime = process.hrtime.bigint();
            const compressionTime = Number(endTime - startTime) / 1000000; // Convert to milliseconds

            // Update statistics
            this.updateStats(inputBuffer.length, compressedBuffer.length, compressionTime);

            const compressionRatio = inputBuffer.length / compressedBuffer.length;

            return {
                compressed: true,
                data: compressedBuffer,
                originalSize: inputBuffer.length,
                compressedSize: compressedBuffer.length,
                compressionRatio: compressionRatio,
                algorithm: algorithm,
                compressionTime: compressionTime
            };

        } catch (error) {
            throw new Error(`Compression failed: ${error.message}`);
        }
    }

    async decompress(compressedData, algorithm = null) {
        try {
            // Auto-detect algorithm if not provided
            if (!algorithm) {
                algorithm = this.detectAlgorithm(compressedData);
            }

            let decompressedBuffer;

            switch (algorithm) {
                case 'gzip':
                    decompressedBuffer = await this.gunzipAsync(compressedData);
                    break;
                    
                case 'deflate':
                    decompressedBuffer = await this.inflateAsync(compressedData);
                    break;
                    
                case 'brotli':
                    decompressedBuffer = await this.brotliDecompressAsync(compressedData);
                    break;
                    
                case 'none':
                    return compressedData;
                    
                default:
                    throw new Error(`Unsupported decompression algorithm: ${algorithm}`);
            }

            return decompressedBuffer;

        } catch (error) {
            throw new Error(`Decompression failed: ${error.message}`);
        }
    }

    detectAlgorithm(buffer) {
        if (!Buffer.isBuffer(buffer) || buffer.length < 2) {
            return 'none';
        }

        // Check magic bytes
        const firstTwo = buffer.readUInt16BE(0);
        
        // Gzip magic bytes: 0x1f8b
        if (firstTwo === 0x1f8b) {
            return 'gzip';
        }
        
        // Deflate typically starts with 0x789c or 0x78da
        if (firstTwo === 0x789c || firstTwo === 0x78da) {
            return 'deflate';
        }
        
        // Brotli doesn't have standard magic bytes, but we can try to detect
        // For now, assume it's not compressed if we can't detect
        return 'none';
    }

    // Streaming compression for large data
    createCompressStream(algorithm = null) {
        algorithm = algorithm || this.options.algorithm;
        
        const options = {
            level: this.options.level,
            chunkSize: this.options.chunkSize
        };

        switch (algorithm) {
            case 'gzip':
                return zlib.createGzip(options);
            case 'deflate':
                return zlib.createDeflate(options);
            case 'brotli':
                return zlib.createBrotliCompress({
                    params: {
                        [zlib.constants.BROTLI_PARAM_QUALITY]: this.options.level
                    }
                });
            default:
                throw new Error(`Unsupported streaming algorithm: ${algorithm}`);
        }
    }

    createDecompressStream(algorithm = null) {
        algorithm = algorithm || this.options.algorithm;

        switch (algorithm) {
            case 'gzip':
                return zlib.createGunzip();
            case 'deflate':
                return zlib.createInflate();
            case 'brotli':
                return zlib.createBrotliDecompress();
            default:
                throw new Error(`Unsupported streaming algorithm: ${algorithm}`);
        }
    }

    // Adaptive compression - choose best algorithm
    async adaptiveCompress(data) {
        const algorithms = ['gzip', 'deflate', 'brotli'];
        const results = [];

        // Test each algorithm
        for (const algorithm of algorithms) {
            try {
                const originalAlgorithm = this.options.algorithm;
                this.options.algorithm = algorithm;
                
                const result = await this.compress(data);
                results.push({
                    algorithm: algorithm,
                    ...result
                });
                
                this.options.algorithm = originalAlgorithm;
            } catch (error) {
                console.warn(`Algorithm ${algorithm} failed:`, error.message);
            }
        }

        // Choose best compression ratio
        if (results.length === 0) {
            throw new Error('All compression algorithms failed');
        }

        results.sort((a, b) => b.compressionRatio - a.compressionRatio);
        return results[0];
    }

    // Batch compression for multiple items
    async compressBatch(items) {
        const results = [];
        
        for (let i = 0; i < items.length; i++) {
            try {
                const result = await this.compress(items[i]);
                results.push({
                    index: i,
                    success: true,
                    ...result
                });
            } catch (error) {
                results.push({
                    index: i,
                    success: false,
                    error: error.message
                });
            }
        }
        
        return results;
    }

    // Compress JSON with schema optimization
    async compressJSON(jsonData, optimizeSchema = true) {
        let dataToCompress = jsonData;
        let schema = null;

        if (optimizeSchema && Array.isArray(jsonData) && jsonData.length > 1) {
            // Extract schema for repeated objects
            const result = this.optimizeJSONSchema(jsonData);
            dataToCompress = result.optimized;
            schema = result.schema;
        }

        const compressed = await this.compress(JSON.stringify(dataToCompress));
        
        return {
            ...compressed,
            schema: schema,
            optimized: !!schema
        };
    }

    optimizeJSONSchema(jsonArray) {
        if (!Array.isArray(jsonArray) || jsonArray.length === 0) {
            return { optimized: jsonArray, schema: null };
        }

        // Extract common keys
        const allKeys = new Set();
        jsonArray.forEach(item => {
            if (typeof item === 'object' && item !== null) {
                Object.keys(item).forEach(key => allKeys.add(key));
            }
        });

        const schema = Array.from(allKeys);
        
        // Convert objects to arrays based on schema
        const optimized = jsonArray.map(item => {
            if (typeof item === 'object' && item !== null) {
                return schema.map(key => item[key]);
            }
            return item;
        });

        return { optimized, schema };
    }

    updateStats(originalSize, compressedSize, compressionTime) {
        this.stats.totalCompressions++;
        this.stats.totalBytes += originalSize;
        this.stats.compressedBytes += compressedSize;
        this.stats.totalTime += compressionTime;
    }

    getStats() {
        const avgCompressionRatio = this.stats.totalBytes > 0 ? 
            this.stats.totalBytes / this.stats.compressedBytes : 1;
        
        const avgCompressionTime = this.stats.totalCompressions > 0 ?
            this.stats.totalTime / this.stats.totalCompressions : 0;

        return {
            totalCompressions: this.stats.totalCompressions,
            totalBytes: this.stats.totalBytes,
            compressedBytes: this.stats.compressedBytes,
            bytesReduced: this.stats.totalBytes - this.stats.compressedBytes,
            averageCompressionRatio: avgCompressionRatio,
            averageCompressionTime: avgCompressionTime,
            totalTime: this.stats.totalTime
        };
    }

    resetStats() {
        this.stats = {
            totalCompressions: 0,
            totalBytes: 0,
            compressedBytes: 0,
            totalTime: 0
        };
    }

    // Configuration methods
    setCompressionLevel(level) {
        if (level < 1 || level > 9) {
            throw new Error('Compression level must be between 1 and 9');
        }
        this.options.level = level;
    }

    setAlgorithm(algorithm) {
        const supportedAlgorithms = ['gzip', 'deflate', 'brotli'];
        if (!supportedAlgorithms.includes(algorithm)) {
            throw new Error(`Unsupported algorithm: ${algorithm}`);
        }
        this.options.algorithm = algorithm;
    }

    setThreshold(threshold) {
        if (threshold < 0) {
            throw new Error('Threshold must be non-negative');
        }
        this.options.threshold = threshold;
    }
}

module.exports = DataCompressor; 