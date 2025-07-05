import React, { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { AlertTriangle, CheckCircle2, Link as LinkIcon, Clock, ExternalLink, RefreshCcw } from 'lucide-react';
import { threatIntelligenceService } from '@/services/threatIntelligenceService';

interface ScanResultsProps {
  results: any;
  type: 'file' | 'url' | 'domain' | 'ip';
}

const ScanResults: React.FC<ScanResultsProps> = ({ results, type }) => {
  const [isCheckingStatus, setIsCheckingStatus] = useState(false);
  const [updatedResults, setUpdatedResults] = useState<any>(null);

  if (!results) return null;

  // Use updated results if available, otherwise use the original results
  const displayResults = updatedResults || results;

  // Check if it's a fresh file upload result
  const isNewlyUploadedFile = 
    type === 'file' && 
    displayResults.data?.meta?.file_info && 
    !displayResults.data?.data?.attributes?.last_analysis_stats;

  const getResourceId = () => {
    if (!displayResults.data) return null;
    
    // For newly uploaded files, use the file hash from metadata, not the analysis ID
    if (isNewlyUploadedFile) {
      // Get file hash in order of preference (sha256, sha1, md5)
      const fileInfo = displayResults.data.meta?.file_info;
      if (fileInfo) {
        return fileInfo.sha256 || fileInfo.sha1 || fileInfo.md5;
      }
      // Fallback to data.id only if it's not a base64 encoded string (which would be an analysis ID)
      const id = displayResults.data.data?.id;
      if (id && !id.includes('=')) {
        return id;
      }
      return null;
    }
    
    return displayResults.data.data?.id;
  };

  const getResourceName = () => {
    if (!displayResults.data) return 'Unknown';
    
    // Handle newly uploaded file
    if (isNewlyUploadedFile) {
      return displayResults.data.meta?.file_info?.name || 'Uploaded File';
    }
    
    if (type === 'file') {
      return displayResults.data.data?.id || 'Unknown File';
    } else if (type === 'url') {
      return displayResults.data.data?.id || 'Unknown URL';
    } else if (type === 'domain') {
      return displayResults.data.data?.id || 'Unknown Domain';
    } else if (type === 'ip') {
      return displayResults.data.data?.id || 'Unknown IP';
    }
    
    return 'Unknown';
  };
  
  const getClassification = () => {
    if (isNewlyUploadedFile) return 'Queued';
    if (!displayResults.data) return 'Unknown';
    
    // Extract stats from the appropriate location in the data
    const stats = displayResults.data.data?.attributes?.last_analysis_stats;
    
    if (stats) {
      if (stats.malicious > 0) {
        return 'Malicious';
      } else if (stats.suspicious > 0) {
        return 'Suspicious';
      } else {
        return 'Clean';
      }
    }
    
    return 'Unknown';
  };
  
  const getDetectionRate = () => {
    if (isNewlyUploadedFile) return { positives: 0, total: 0, isQueued: true };
    if (!displayResults.data) return { positives: 0, total: 0 };
    
    const stats = displayResults.data.data?.attributes?.last_analysis_stats;
    
    if (stats) {
      const total = Object.values(stats).reduce((sum: number, val: any) => sum + val, 0);
      const positives = stats.malicious + stats.suspicious;
      
      return { positives, total };
    }
    
    return { positives: 0, total: 0 };
  };
  
  const getEngineResults = () => {
    if (isNewlyUploadedFile) return {};
    if (!displayResults.data) return {};
    
    const analysisResults = displayResults.data.data?.attributes?.last_analysis_results;
    
    if (analysisResults) {
      return analysisResults;
    }
    
    return {};
  };
  
  const getPermalink = () => {
    if (isNewlyUploadedFile) {
      // If we have a file hash use it for the permalink
      const fileInfo = displayResults.data.meta?.file_info;
      if (fileInfo) {
        const hash = fileInfo.sha256 || fileInfo.sha1 || fileInfo.md5;
        if (hash) return `https://www.virustotal.com/gui/file/${hash}/detection`;
      }
      
      // Fallback to data.id only if it's not a base64 encoded ID
      const id = displayResults.data.data?.id;
      if (id && !id.includes('=')) {
        return `https://www.virustotal.com/gui/file/${id}/detection`;
      }
      
      return '#';
    }
    
    if (!displayResults.data) return '#';
    
    if (type === 'file') {
      const hash = displayResults.data.data?.id;
      return `https://www.virustotal.com/gui/file/${hash}/detection`;
    } else if (type === 'url') {
      const id = displayResults.data.data?.id;
      return `https://www.virustotal.com/gui/url/${id}/detection`;
    } else if (type === 'domain') {
      const domain = displayResults.data.data?.id;
      return `https://www.virustotal.com/gui/domain/${domain}/detection`;
    } else if (type === 'ip') {
      const ip = displayResults.data.data?.id;
      return `https://www.virustotal.com/gui/ip-address/${ip}/detection`;
    }
    
    return '#';
  };
  
  const getScanDate = () => {
    if (isNewlyUploadedFile) return new Date().toLocaleString();
    if (!displayResults.data) return 'Unknown';
    
    return displayResults.data.data?.attributes?.last_analysis_date
      ? new Date(displayResults.data.data.attributes.last_analysis_date * 1000).toLocaleString()
      : new Date(displayResults.timestamp).toLocaleString();
  };

  const getFileInfo = () => {
    if (!isNewlyUploadedFile) return null;
    
    const fileInfo = displayResults.data.meta?.file_info;
    if (!fileInfo) return null;
    
    return {
      size: fileInfo.size ? (fileInfo.size / (1024 * 1024)).toFixed(2) + ' MB' : 'Unknown size',
      type: fileInfo.type || 'Unknown type',
      md5: fileInfo.md5,
      sha1: fileInfo.sha1,
      sha256: fileInfo.sha256
    };
  };

  // Function to check the status of a submitted file
  const checkFileStatus = async () => {
    const resourceId = getResourceId();
    if (!resourceId || type !== 'file') {
      console.error('Cannot check status: Missing or invalid resource ID');
      return;
    }
    
    setIsCheckingStatus(true);
    
    try {
      console.log('Checking status for file hash:', resourceId);
      const response = await threatIntelligenceService.getFileReport(resourceId);
      console.log('Status check response:', response);
      
      if (response.success) {
        setUpdatedResults(response);
      }
    } catch (error) {
      console.error('Failed to check file status:', error);
    } finally {
      setIsCheckingStatus(false);
    }
  };
  
  const classification = getClassification();
  const { positives, total, isQueued } = getDetectionRate();
  const engineResults = getEngineResults();
  const resourceName = getResourceName();
  const permalink = getPermalink();
  const scanDate = getScanDate();
  const fileInfo = getFileInfo();
  const resourceId = getResourceId();

  return (
    <Card className="bg-cyber-gray border-cyber-lightgray">
      <CardHeader className="pb-2">
        <CardTitle className="text-lg font-medium text-white">Scan Results</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="bg-cyber-darker p-4 rounded-md border border-cyber-lightgray">
          <div className="flex justify-between items-start mb-4">
            <div>
              <h3 className="text-lg font-medium text-white">{resourceName}</h3>
              <div className="flex items-center text-xs text-gray-400 mt-1">
                <Clock className="h-3 w-3 mr-1" />
                <span>Scanned on {scanDate}</span>
              </div>
              {isNewlyUploadedFile && resourceId && (
                <div className="text-xs text-gray-400 mt-1">
                  <span className="font-mono">{resourceId.substring(0, 16)}...</span>
                </div>
              )}
            </div>
            <Badge className={
              classification === "Clean" ? "bg-cyber-success" :
              classification === "Suspicious" ? "bg-cyber-warning" : 
              classification === "Malicious" ? "bg-cyber-danger" :
              classification === "Queued" ? "bg-cyber-info" :
              "bg-cyber-gray"
            }>
              {classification.toUpperCase()}
            </Badge>
          </div>
          
          {isNewlyUploadedFile && fileInfo && (
            <div className="mb-4 bg-cyber-gray p-3 rounded-md">
              <h4 className="text-sm font-medium text-white mb-2">File Information</h4>
              <div className="grid grid-cols-1 gap-1">
                <div className="flex justify-between">
                  <span className="text-xs text-gray-400">Size:</span>
                  <span className="text-xs text-white">{fileInfo.size}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-xs text-gray-400">Type:</span>
                  <span className="text-xs text-white">{fileInfo.type}</span>
                </div>
                {fileInfo.md5 && (
                  <div className="flex justify-between">
                    <span className="text-xs text-gray-400">MD5:</span>
                    <span className="text-xs text-white font-mono">{fileInfo.md5}</span>
                  </div>
                )}
                {fileInfo.sha256 && (
                  <div className="flex justify-between">
                    <span className="text-xs text-gray-400">SHA-256:</span>
                    <span className="text-xs text-white font-mono truncate max-w-xs">{fileInfo.sha256}</span>
                  </div>
                )}
              </div>
            </div>
          )}
          
          {isQueued ? (
            <div className="mb-4 bg-cyber-gray p-4 rounded-md text-center">
              <RefreshCcw className="h-5 w-5 text-cyber-info mx-auto mb-2 animate-spin" />
              <p className="text-white text-sm">File has been submitted for analysis</p>
              <p className="text-gray-400 text-xs mt-1">Analysis results can take a few minutes</p>
              <Button 
                onClick={checkFileStatus}
                disabled={isCheckingStatus || !resourceId}
                size="sm"
                variant="outline"
                className="mt-3 text-cyber-accent border-cyber-accent hover:bg-cyber-accent/20"
              >
                {isCheckingStatus ? (
                  <>
                    <RefreshCcw className="h-3 w-3 mr-1 animate-spin" />
                    Checking...
                  </>
                ) : (
                  <>
                    <RefreshCcw className="h-3 w-3 mr-1" />
                    Check Analysis Status
                  </>
                )}
              </Button>
            </div>
          ) : (
            <div className="mb-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-300">Detection Rate</span>
                <span className="text-sm text-white">
                  {positives}/{total} engines
                </span>
              </div>
              <div className="h-2 bg-cyber-gray rounded-full overflow-hidden">
                <div 
                  className={`h-full ${
                    positives / total < 0.2 ? "bg-cyber-success" :
                    positives / total < 0.5 ? "bg-cyber-warning" :
                    "bg-cyber-danger"
                  }`}
                  style={{ width: `${(positives / total) * 100 || 0}%` }}
                ></div>
              </div>
            </div>
          )}
          
          {Object.keys(engineResults).length > 0 && (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-white mb-2">Engine Results</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-64 overflow-y-auto">
                {Object.entries(engineResults).slice(0, 10).map(([engine, data]: [string, any]) => (
                  <div key={engine} className="flex items-center justify-between p-2 bg-cyber-gray rounded-md">
                    <div className="flex items-center">
                      {data.category === "malicious" || data.category === "suspicious" ? (
                        <AlertTriangle className="h-4 w-4 text-cyber-danger mr-2" />
                      ) : (
                        <CheckCircle2 className="h-4 w-4 text-cyber-success mr-2" />
                      )}
                      <span className="text-sm text-white">{engine}</span>
                    </div>
                    <span className="text-xs text-gray-300 truncate max-w-32">
                      {data.result || data.category || "Clean"}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          <div className="flex justify-end">
            <Button
              variant="outline"
              size="sm"
              className="text-cyber-accent border-cyber-accent hover:bg-cyber-accent/20"
              onClick={() => window.open(permalink, '_blank')}
            >
              <ExternalLink className="h-3 w-3 mr-1" />
              View Full Report
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default ScanResults; 