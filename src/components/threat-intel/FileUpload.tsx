import React, { useState, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { AlertCircle, FileUp, X, CheckCircle, Loader2 } from 'lucide-react';
import { threatIntelligenceService } from '@/services/threatIntelligenceService';

interface FileUploadProps {
  onUploadComplete: (result: any) => void;
}

const FileUpload: React.FC<FileUploadProps> = ({ onUploadComplete }) => {
  const [file, setFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [uploadSuccess, setUploadSuccess] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Update max file size to match VirusTotal's limit
  const maxFileSizeMB = 32; // VirusTotal API supports up to 32MB direct upload

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
      setError(null);
      setUploadSuccess(false);
    }
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setFile(e.dataTransfer.files[0]);
      setError(null);
      setUploadSuccess(false);
    }
  };

  const handleRemoveFile = () => {
    setFile(null);
    setError(null);
    setUploadSuccess(false);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    
    setIsUploading(true);
    setError(null);
    
    try {
      console.log('Starting file upload:', file.name, file.size);
      
      // For simplicity, focus on standard upload for files <= 32MB
      if (file.size > 32 * 1024 * 1024) {
        setError('File is too large. Please upload a file smaller than 32MB.');
        setIsUploading(false);
        return;
      }
      
      // Create form data
      const formData = new FormData();
      formData.append('file', file);
      
      // For debugging, log headers
      console.log('Upload headers:', {
        'Content-Type': 'multipart/form-data',
        'x-api-key': 'API key is set in apiClient'
      });
      
      const response = await threatIntelligenceService.uploadFile(file);
      console.log('Upload response:', JSON.stringify(response, null, 2));
      
      if (response.success) {
        setUploadSuccess(true);
        
        // Ensure we have the necessary file hash information
        if (response.data?.meta?.file_info) {
          const fileInfo = response.data.meta.file_info;
          console.log('File hash information:', {
            md5: fileInfo.md5,
            sha1: fileInfo.sha1,
            sha256: fileInfo.sha256
          });
        }
        
        onUploadComplete(response.data);
      } else {
        throw new Error(response.error || 'Unknown error during file upload');
      }
    } catch (err: any) {
      console.error('File upload error details:', err);
      
      // Try to extract the most useful error message
      let errorMessage = 'Failed to upload file. Please try again.';
      
      if (err.response?.data?.error) {
        errorMessage = err.response.data.error;
      } else if (err.message) {
        errorMessage = err.message;
      }
      
      setError(errorMessage);
    } finally {
      setIsUploading(false);
    }
  };

  const isFileTooLarge = file && file.size > maxFileSizeMB * 1024 * 1024;

  return (
    <Card className="bg-cyber-gray border-cyber-lightgray">
      <CardHeader className="pb-2">
        <CardTitle className="text-lg font-medium text-white">File Analysis</CardTitle>
      </CardHeader>
      <CardContent>
        <div
          className={`border-2 border-dashed rounded-md p-6 ${
            file ? 'border-cyber-accent bg-cyber-accent/10' : 'border-cyber-lightgray'
          } text-center cursor-pointer`}
          onDragOver={handleDragOver}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
        >
          <input
            type="file"
            className="hidden"
            ref={fileInputRef}
            onChange={handleFileChange}
          />
          
          {!file && (
            <div className="text-center">
              <FileUp className="h-12 w-12 text-cyber-accent mx-auto mb-2" />
              <p className="text-white font-medium mb-1">Drag and drop a file here or click to browse</p>
              <p className="text-gray-400 text-sm">Max file size: {maxFileSizeMB}MB</p>
            </div>
          )}
          
          {file && (
            <div className="text-left">
              <div className="flex justify-between items-center mb-2">
                <div className="flex items-center text-white font-medium">
                  <FileUp className="h-5 w-5 text-cyber-accent mr-2" />
                  <span className="truncate max-w-xs">{file.name}</span>
                </div>
                <button 
                  onClick={(e) => { 
                    e.stopPropagation(); 
                    handleRemoveFile(); 
                  }}
                  className="text-gray-400 hover:text-white"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
              
              <div className="flex justify-between text-sm text-gray-400">
                <span>{(file.size / (1024 * 1024)).toFixed(2)} MB</span>
                <span>{file.type || 'Unknown type'}</span>
              </div>
              
              {isFileTooLarge && (
                <div className="mt-2 flex items-center text-cyber-danger text-sm">
                  <AlertCircle className="h-4 w-4 mr-1" />
                  File exceeds the maximum size of {maxFileSizeMB}MB
                </div>
              )}
              
              {uploadSuccess && (
                <div className="mt-2 flex items-center text-cyber-success text-sm">
                  <CheckCircle className="h-4 w-4 mr-1" />
                  File uploaded successfully
                </div>
              )}
              
              {error && (
                <div className="mt-2 flex items-center text-cyber-danger text-sm">
                  <AlertCircle className="h-4 w-4 mr-1" />
                  {error}
                </div>
              )}
            </div>
          )}
        </div>
        
        <div className="mt-4">
          <Button
            onClick={(e) => { 
              e.stopPropagation(); 
              handleUpload(); 
            }}
            disabled={!file || isUploading || isFileTooLarge}
            className="w-full bg-cyber-accent hover:bg-cyber-accent/80"
          >
            {isUploading ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Uploading...
              </>
            ) : (
              <>
                <FileUp className="h-4 w-4 mr-2" />
                Upload for Analysis
              </>
            )}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
};

export default FileUpload; 