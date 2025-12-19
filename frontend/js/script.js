/**
 * QR Code Security Scanner Frontend
 * Deployed on InfinityFree
 */

class QRScanner {
    constructor() {
        this.apiEndpoint = 'https://your-render-app.onrender.com';
        this.scanHistory = [];
        this.totalScans = 0;
        this.safeCount = 0;
        this.maliciousCount = 0;
        
        this.initialize();
    }
    
    initialize() {
        // DOM Elements
        this.elements = {
            uploadTab: document.getElementById('upload-tab'),
            urlTab: document.getElementById('url-tab'),
            directUrlTab: document.getElementById('direct-url-tab'),
            uploadContent: document.getElementById('upload-content'),
            urlContent: document.getElementById('url-content'),
            directUrlContent: document.getElementById('direct-url-content'),
            dropArea: document.getElementById('drop-area'),
            browseBtn: document.getElementById('browse-btn'),
            fileInput: document.getElementById('file-input'),
            imagePreview: document.getElementById('image-preview'),
            imageUrlInput: document.getElementById('image-url'),
            scanUrlBtn: document.getElementById('scan-url-btn'),
            directUrlInput: document.getElementById('direct-url'),
            analyzeUrlBtn: document.getElementById('analyze-url-btn'),
            apiEndpointInput: document.getElementById('api-endpoint'),
            testApiBtn: document.getElementById('test-api-btn'),
            loading: document.getElementById('loading'),
            results: document.getElementById('results'),
            statistics: document.getElementById('statistics'),
            totalScansEl: document.getElementById('total-scans'),
            safeCountEl: document.getElementById('safe-count'),
            maliciousCountEl: document.getElementById('malicious-count'),
            detectionRateEl: document.getElementById('detection-rate'),
            backendStatus: document.getElementById('backend-status')
        };
        
        // Event Listeners
        this.setupEventListeners();
        
        // Test backend connection on load
        this.testBackendConnection();
    }
    
    setupEventListeners() {
        // Tab switching
        this.elements.uploadTab.addEventListener('click', () => this.switchTab('upload'));
        this.elements.urlTab.addEventListener('click', () => this.switchTab('url'));
        this.elements.directUrlTab.addEventListener('click', () => this.switchTab('direct-url'));
        
        // File upload
        this.elements.browseBtn.addEventListener('click', () => this.elements.fileInput.click());
        this.elements.fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        
        // Drag and drop
        this.setupDragAndDrop();
        
        // URL scanning
        this.elements.scanUrlBtn.addEventListener('click', () => this.scanImageUrl());
        this.elements.imageUrlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.scanImageUrl();
        });
        
        // Direct URL analysis
        this.elements.analyzeUrlBtn.addEventListener('click', () => this.analyzeDirectUrl());
        this.elements.directUrlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.analyzeDirectUrl();
        });
        
        // API endpoint
        this.elements.apiEndpointInput.addEventListener('change', () => {
            this.apiEndpoint = this.elements.apiEndpointInput.value;
            this.testBackendConnection();
        });
        this.elements.testApiBtn.addEventListener('click', () => this.testBackendConnection());
    }
    
    setupDragAndDrop() {
        const dropArea = this.elements.dropArea;
        
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropArea.addEventListener(eventName, preventDefaults, false);
        });
        
        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }
        
        ['dragenter', 'dragover'].forEach(eventName => {
            dropArea.addEventListener(eventName, () => {
                dropArea.classList.add('dragover');
            }, false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            dropArea.addEventListener(eventName, () => {
                dropArea.classList.remove('dragover');
            }, false);
        });
        
        dropArea.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            this.handleFiles(files);
        }, false);
    }
    
    switchTab(tabName) {
        // Update tabs
        document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        
        switch(tabName) {
            case 'upload':
                this.elements.uploadTab.classList.add('active');
                this.elements.uploadContent.classList.add('active');
                break;
            case 'url':
                this.elements.urlTab.classList.add('active');
                this.elements.urlContent.classList.add('active');
                break;
            case 'direct-url':
                this.elements.directUrlTab.classList.add('active');
                this.elements.directUrlContent.classList.add('active');
                break;
        }
    }
    
    handleFileSelect(event) {
        const files = event.target.files;
        this.handleFiles(files);
    }
    
    handleFiles(files) {
        if (files.length === 0) return;
        
        const file = files[0];
        
        // Preview image
        const reader = new FileReader();
        reader.onload = (e) => {
            this.elements.imagePreview.innerHTML = `
                <img src="${e.target.result}" alt="QR Code Preview">
                <p>${file.name} (${Math.round(file.size / 1024)} KB)</p>
                <button class="btn-scan" onclick="scanner.scanUploadedImage()">Scan This QR Code</button>
            `;
        };
        reader.readAsDataURL(file);
        
        // Store file for scanning
        this.currentFile = file;
    }
    
    async scanUploadedImage() {
        if (!this.currentFile) {
            this.showError('Please select an image file first');
            return;
        }
        
        const formData = new FormData();
        formData.append('image_file', this.currentFile);
        
        await this.scanQR(formData);
    }
    
    async scanImageUrl() {
        const imageUrl = this.elements.imageUrlInput.value.trim();
        
        if (!imageUrl) {
            this.showError('Please enter an image URL');
            return;
        }
        
        if (!this.isValidUrl(imageUrl)) {
            this.showError('Please enter a valid URL');
            return;
        }
        
        const payload = { image_url: imageUrl };
        await this.scanQR(payload);
    }
    
    async analyzeDirectUrl() {
        const url = this.elements.directUrlInput.value.trim();
        
        if (!url) {
            this.showError('Please enter a URL to analyze');
            return;
        }
        
        if (!this.isValidUrl(url)) {
            this.showError('Please enter a valid URL');
            return;
        }
        
        await this.analyzeUrl(url);
    }
    
    async scanQR(payload) {
        this.showLoading(true);
        
        try {
            let response;
            
            if (payload instanceof FormData) {
                // File upload
                response = await fetch(`${this.apiEndpoint}/api/scan`, {
                    method: 'POST',
                    body: payload
                });
            } else {
                // JSON payload
                response = await fetch(`${this.apiEndpoint}/api/scan`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
            }
            
            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(result.error || 'Scan failed');
            }
            
            this.displayResults(result);
            this.updateStatistics(result);
            
        } catch (error) {
            this.showError(`Scan failed: ${error.message}`);
        } finally {
            this.showLoading(false);
        }
    }
    
    async analyzeUrl(url) {
        this.showLoading(true);
        
        try {
            const response = await fetch(`${this.apiEndpoint}/api/analyze/url`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            
            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(result.error || 'Analysis failed');
            }
            
            // Format result to match scan results structure
            const formattedResult = {
                success: true,
                scan_summary: 'Direct URL analysis',
                predictions: [{
                    extracted_data: url,
                    analysis: result,
                    type: 'direct_url'
                }],
                timestamp: new Date().toISOString()
            };
            
            this.displayResults(formattedResult);
            this.updateStatistics(formattedResult);
            
        } catch (error) {
            this.showError(`Analysis failed: ${error.message}`);
        } finally {
            this.showLoading(false);
        }
    }
    
    displayResults(result) {
        if (!result.success || !result.predictions || result.predictions.length === 0) {
            this.elements.results.innerHTML = `
                <div class="result-card">
                    <h3>No QR Codes Found</h3>
                    <p>${result.message || 'Could not extract QR code from image'}</p>
                </div>
            `;
            return;
        }
        
        let html = '';
        
        result.predictions.forEach((prediction, index) => {
            const isMalicious = prediction.analysis?.is_malicious === true;
            const confidence = prediction.analysis?.confidence || 0;
            const riskLevel = prediction.analysis?.risk_level || 'Unknown';
            
            html += `
                <div class="result-card ${isMalicious ? 'malicious' : 'safe'}">
                    <h3>QR Code ${index + 1}</h3>
                    
                    <div class="url-display">
                        ${this.escapeHtml(prediction.extracted_data)}
                    </div>
                    
                    <div class="status-badge ${isMalicious ? 'status-malicious' : 'status-safe'}">
                        ${isMalicious ? '⚠️ MALICIOUS' : '✅ SAFE'}
                    </div>
                    
                    ${prediction.analysis ? `
                        <p><strong>Confidence:</strong> ${(confidence * 100).toFixed(1)}%</p>
                        <p><strong>Risk Level:</strong> ${riskLevel}</p>
                        
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: ${confidence * 100}%"></div>
                        </div>
                        
                        <p><strong>Message:</strong> ${prediction.analysis.message || 'No additional information'}</p>
                        
                        <div class="details">
                            <p><small>Analyzed at: ${new Date(result.timestamp).toLocaleString()}</small></p>
                        </div>
                    ` : `
                        <p class="error">${prediction.error || 'Analysis failed'}</p>
                    `}
                </div>
            `;
        });
        
        this.elements.results.innerHTML = html;
        
        // Store in history
        this.scanHistory.push({
            timestamp: new Date().toISOString(),
            result: result,
            source: 'scan'
        });
        
        this.totalScans++;
        this.updateStatsDisplay();
    }
    
    updateStatistics(result) {
        if (!result.predictions) return;
        
        result.predictions.forEach(prediction => {
            if (prediction.analysis?.is_malicious === true) {
                this.maliciousCount++;
            } else if (prediction.analysis?.is_malicious === false) {
                this.safeCount++;
            }
        });
        
        this.updateStatsDisplay();
        this.elements.statistics.style.display = 'block';
    }
    
    updateStatsDisplay() {
        this.elements.totalScansEl.textContent = this.totalScans;
        this.elements.safeCountEl.textContent = this.safeCount;
        this.elements.maliciousCountEl.textContent = this.maliciousCount;
        
        const detectionRate = this.totalScans > 0 
            ? ((this.safeCount + this.maliciousCount) / this.totalScans * 100).toFixed(1)
            : 0;
        this.elements.detectionRateEl.textContent = `${detectionRate}%`;
    }
    
    async testBackendConnection() {
        this.apiEndpoint = this.elements.apiEndpointInput.value;
        
        try {
            const response = await fetch(`${this.apiEndpoint}/api/health`, {
                method: 'GET',
                timeout: 5000
            });
            
            if (response.ok) {
                const data = await response.json();
                this.elements.backendStatus.textContent = 'Connected ✓';
                this.elements.backendStatus.className = 'connected';
                console.log('Backend connected:', data);
            } else {
                throw new Error('Health check failed');
            }
        } catch (error) {
            this.elements.backendStatus.textContent = 'Disconnected ✗';
            this.elements.backendStatus.className = '';
            console.error('Backend connection failed:', error);
        }
    }
    
    showLoading(show) {
        this.elements.loading.style.display = show ? 'block' : 'none';
        this.elements.results.style.display = show ? 'none' : 'block';
    }
    
    showError(message) {
        this.elements.results.innerHTML = `
            <div class="result-card malicious">
                <h3>Error</h3>
                <p>${message}</p>
                <button class="btn-scan" onclick="scanner.retryLastScan()">Retry</button>
            </div>
        `;
        this.showLoading(false);
    }
    
    retryLastScan() {
        // Implement retry logic if needed
        alert('Please try scanning again');
    }
    
    isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize scanner when page loads
let scanner;
document.addEventListener('DOMContentLoaded', () => {
    scanner = new QRScanner();
});