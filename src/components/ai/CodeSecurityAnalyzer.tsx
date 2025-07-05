import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Button } from '../ui/button';
import { Textarea } from '../ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { Badge } from '../ui/badge';
import { Alert, AlertDescription } from '../ui/alert';
import { Progress } from '../ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs';
import { Separator } from '../ui/separator';
import { 
  Code, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Upload, 
  Download,
  Play,
  RotateCcw,
  Copy,
  Eye,
  EyeOff
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface CodeSecurityAnalyzerProps {
  onClose?: () => void;
}

interface Vulnerability {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  location?: string;
  recommendation: string;
}

interface AnalysisResult {
  summary: string;
  vulnerabilities: Vulnerability[];
  recommendations: string[];
  securityScore: number;
}

const CodeSecurityAnalyzer: React.FC<CodeSecurityAnalyzerProps> = ({ onClose }) => {
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState('javascript');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showPreview, setShowPreview] = useState(false);
  const { toast } = useToast();

  // Sample code templates for different languages
  const codeTemplates = {
    javascript: `// Sample JavaScript code with potential security issues
const express = require('express');
const mysql = require('mysql');
const app = express();

app.use(express.json());

// Database connection with hardcoded credentials
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password123', // Hardcoded password
  database: 'users'
});

// Vulnerable SQL query endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // SQL injection vulnerability
  const query = \`SELECT * FROM users WHERE username = '\${username}' AND password = '\${password}'\`;
  
  db.query(query, (err, results) => {
    if (err) {
      // Information disclosure
      res.status(500).json({ error: err.message });
      return;
    }
    
    if (results.length > 0) {
      res.json({ success: true, user: results[0] });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`,
    python: `# Sample Python code with potential security issues
import sqlite3
import hashlib
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# Hardcoded secret key
app.secret_key = 'my-secret-key-123'

# Database connection
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    conn = get_db_connection()
    
    // SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    user = conn.execute(query).fetchone()
    
    conn.close()
    
    if user:
        return jsonify({'success': True, 'user_id': user['id']})
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    // Path traversal vulnerability
    filename = request.form.get('filename', file.filename)
    filepath = os.path.join('/uploads', filename)
    
    file.save(filepath)
    return jsonify({'message': 'File uploaded successfully'})

if __name__ == '__main__':
    // Debug mode in production
    app.run(debug=True, host='0.0.0.0')`,
    java: `// Sample Java code with potential security issues
import java.sql.*;
import java.io.*;
import javax.servlet.http.*;
import javax.servlet.annotation.WebServlet;

@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    
    // Hardcoded database credentials
    private static final String DB_URL = "jdbc:mysql://localhost:3306/users";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "admin123";
    
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // SQL injection vulnerability
            String query = "SELECT * FROM users WHERE username = '" + username + 
                          "' AND password = '" + password + "'";
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                // Session fixation vulnerability
                HttpSession session = request.getSession(true);
                session.setAttribute("user_id", rs.getString("id"));
                
                response.getWriter().write("Login successful");
            } else {
                response.getWriter().write("Invalid credentials");
            }
            
            conn.close();
            
        } catch (SQLException e) {
            // Information disclosure
            response.getWriter().write("Database error: " + e.getMessage());
        }
    }
}`
  };

  const analyzeCode = async () => {
    if (!code.trim()) {
      setError('Please enter some code to analyze');
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    setAnalysisResult(null);

    try {
      const response = await fetch('/api/v1/ai-insights/deepseek/analyze-code', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': 'fe137543d8e99aa75ab1d3b8812bc2042ddf53caa80934f687a9c98e93d176b0'
        },
        body: JSON.stringify({
          code,
          language
        })
      });

      const result = await response.json();

      if (result.success) {
        setAnalysisResult(result.data);
        toast({
          title: "Analysis Complete",
          description: "Code security analysis has been completed successfully.",
        });
      } else {
        setError(result.error || 'Analysis failed');
      }
    } catch (err) {
      setError('Failed to analyze code. Please try again.');
      console.error('Code analysis error:', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-600 text-white';
      case 'high': return 'bg-orange-600 text-white';
      case 'medium': return 'bg-yellow-600 text-black';
      case 'low': return 'bg-blue-600 text-white';
      case 'info': return 'bg-gray-600 text-white';
      default: return 'bg-gray-600 text-white';
    }
  };

  const getSecurityScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-400';
    if (score >= 60) return 'text-yellow-400';
    if (score >= 40) return 'text-orange-400';
    return 'text-red-400';
  };

  const loadTemplate = (lang: string) => {
    setLanguage(lang);
    setCode(codeTemplates[lang as keyof typeof codeTemplates] || '');
    setAnalysisResult(null);
    setError(null);
  };

  const clearCode = () => {
    setCode('');
    setAnalysisResult(null);
    setError(null);
  };

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(code);
      toast({
        title: "Copied",
        description: "Code copied to clipboard.",
      });
    } catch (err) {
      console.error('Failed to copy to clipboard:', err);
    }
  };

  const exportResults = () => {
    if (!analysisResult) return;
    
    const report = {
      analysis: analysisResult,
      code,
      language,
      timestamp: new Date().toISOString()
    };
    
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-analysis-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <Card className="w-full max-w-7xl h-[90vh] bg-cyber-gray border-cyber-lightgray overflow-hidden">
        <CardHeader className="border-b border-cyber-lightgray">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="flex items-center justify-center w-10 h-10 bg-cyber-primary rounded-lg">
                <Code className="h-6 w-6 text-white" />
              </div>
              <div>
                <CardTitle className="text-xl text-white">Code Security Analyzer</CardTitle>
                <p className="text-sm text-gray-400">AI-powered security vulnerability detection</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowPreview(!showPreview)}
                className="flex items-center gap-2"
              >
                {showPreview ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                {showPreview ? 'Hide Preview' : 'Show Preview'}
              </Button>
              {onClose && (
                <Button variant="outline" onClick={onClose} className="text-white">
                  Close
                </Button>
              )}
            </div>
          </div>
        </CardHeader>
        
        <CardContent className="p-6 h-full overflow-hidden">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 h-full">
            {/* Left Panel - Code Input */}
            <div className="flex flex-col h-full">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <Select value={language} onValueChange={setLanguage}>
                    <SelectTrigger className="w-40">
                      <SelectValue placeholder="Language" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="javascript">JavaScript</SelectItem>
                      <SelectItem value="python">Python</SelectItem>
                      <SelectItem value="java">Java</SelectItem>
                      <SelectItem value="csharp">C#</SelectItem>
                      <SelectItem value="php">PHP</SelectItem>
                      <SelectItem value="go">Go</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => loadTemplate(language)}
                    className="flex items-center gap-2"
                  >
                    <Upload className="h-4 w-4" />
                    Load Template
                  </Button>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={copyToClipboard}
                    className="flex items-center gap-2"
                  >
                    <Copy className="h-4 w-4" />
                    Copy
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={clearCode}
                    className="flex items-center gap-2"
                  >
                    <RotateCcw className="h-4 w-4" />
                    Clear
                  </Button>
                </div>
              </div>
              
              <Textarea
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="Paste your code here for security analysis..."
                className="flex-1 font-mono text-sm bg-cyber-darker border-cyber-lightgray text-white min-h-[400px] resize-none"
              />
              
              <div className="flex items-center justify-between mt-4">
                <div className="text-sm text-gray-400">
                  Lines: {code.split('\n').length} | Characters: {code.length}
                </div>
                <Button
                  onClick={analyzeCode}
                  disabled={isAnalyzing || !code.trim()}
                  className="flex items-center gap-2 bg-cyber-primary hover:bg-cyber-primary/80"
                >
                  {isAnalyzing ? (
                    <div className="h-4 w-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <Play className="h-4 w-4" />
                  )}
                  {isAnalyzing ? 'Analyzing...' : 'Analyze Code'}
                </Button>
              </div>
            </div>
            
            {/* Right Panel - Results */}
            <div className="flex flex-col h-full">
              {error && (
                <Alert className="mb-4 border-red-500 bg-red-900/20">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription className="text-red-300">{error}</AlertDescription>
                </Alert>
              )}
              
              {isAnalyzing && (
                <Card className="mb-4 bg-cyber-darker border-cyber-lightgray">
                  <CardContent className="p-6">
                    <div className="flex items-center gap-3">
                      <div className="h-8 w-8 border-2 border-cyber-primary border-t-transparent rounded-full animate-spin" />
                      <div>
                        <p className="text-white font-medium">Analyzing Code...</p>
                        <p className="text-sm text-gray-400">AI is reviewing your code for security vulnerabilities</p>
                      </div>
                    </div>
                    <Progress value={75} className="mt-4" />
                  </CardContent>
                </Card>
              )}
              
              {analysisResult && (
                <div className="flex-1 overflow-auto">
                  <Tabs defaultValue="overview" className="h-full">
                    <div className="flex items-center justify-between mb-4">
                      <TabsList className="grid w-full grid-cols-3">
                        <TabsTrigger value="overview">Overview</TabsTrigger>
                        <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
                        <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
                      </TabsList>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={exportResults}
                        className="flex items-center gap-2"
                      >
                        <Download className="h-4 w-4" />
                        Export
                      </Button>
                    </div>
                    
                    <TabsContent value="overview" className="space-y-4">
                      <Card className="bg-cyber-darker border-cyber-lightgray">
                        <CardHeader>
                          <CardTitle className="text-white flex items-center gap-2">
                            <Shield className="h-5 w-5" />
                            Security Score
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="flex items-center gap-4">
                            <div className={`text-3xl font-bold ${getSecurityScoreColor(analysisResult.securityScore)}`}>
                              {analysisResult.securityScore}/100
                            </div>
                            <div className="flex-1">
                              <Progress value={analysisResult.securityScore} className="h-3" />
                              <p className="text-sm text-gray-400 mt-1">
                                {analysisResult.securityScore >= 80 ? 'Excellent' :
                                 analysisResult.securityScore >= 60 ? 'Good' :
                                 analysisResult.securityScore >= 40 ? 'Fair' : 'Poor'} security posture
                              </p>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                      
                      <Card className="bg-cyber-darker border-cyber-lightgray">
                        <CardHeader>
                          <CardTitle className="text-white">Analysis Summary</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <p className="text-gray-300">{analysisResult.summary}</p>
                          <div className="grid grid-cols-2 gap-4 mt-4">
                            <div className="text-center">
                              <div className="text-2xl font-bold text-red-400">
                                {analysisResult.vulnerabilities.length}
                              </div>
                              <div className="text-sm text-gray-400">Vulnerabilities Found</div>
                            </div>
                            <div className="text-center">
                              <div className="text-2xl font-bold text-blue-400">
                                {analysisResult.recommendations.length}
                              </div>
                              <div className="text-sm text-gray-400">Recommendations</div>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </TabsContent>
                    
                    <TabsContent value="vulnerabilities" className="space-y-3">
                      {analysisResult.vulnerabilities.map((vuln, index) => (
                        <Card key={index} className="bg-cyber-darker border-cyber-lightgray">
                          <CardContent className="p-4">
                            <div className="flex items-start justify-between mb-2">
                              <Badge className={getSeverityColor(vuln.severity)} variant="secondary">
                                {vuln.severity.toUpperCase()}
                              </Badge>
                              {vuln.location && (
                                <span className="text-xs text-gray-400">{vuln.location}</span>
                              )}
                            </div>
                            <h4 className="text-white font-medium mb-2">{vuln.description}</h4>
                            <p className="text-sm text-gray-300 mb-2">{vuln.recommendation}</p>
                          </CardContent>
                        </Card>
                      ))}
                    </TabsContent>
                    
                    <TabsContent value="recommendations" className="space-y-3">
                      {analysisResult.recommendations.map((rec, index) => (
                        <Card key={index} className="bg-cyber-darker border-cyber-lightgray">
                          <CardContent className="p-4">
                            <div className="flex items-start gap-3">
                              <CheckCircle className="h-5 w-5 text-green-400 mt-0.5" />
                              <p className="text-gray-300">{rec}</p>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </TabsContent>
                  </Tabs>
                </div>
              )}
              
              {!analysisResult && !isAnalyzing && !error && (
                <div className="flex-1 flex items-center justify-center">
                  <div className="text-center">
                    <Code className="h-16 w-16 text-gray-500 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-white mb-2">Ready to Analyze</h3>
                    <p className="text-gray-400 max-w-md">
                      Paste your code in the editor and click "Analyze Code" to get AI-powered security insights and vulnerability detection.
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default CodeSecurityAnalyzer; 