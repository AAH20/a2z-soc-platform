
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { Progress } from '@/components/ui/progress';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { Brain, RefreshCw, Save, AlertCircle, CheckCircle2 } from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";

export type ModelType = 'gpt' | 'claude' | 'gemini' | 'security-copilot';

export interface ModelConfig {
  type: ModelType;
  name: string;
  description: string;
  apiKey?: string;
  endpoint?: string;
  maxTokens?: number;
  temperature?: number;
  status: 'connected' | 'disconnected' | 'error';
  lastSync?: string;
  icon?: React.ReactNode;
  color?: string;
}

interface ModelInterfaceProps {
  model: ModelConfig;
  onSaveConfig?: (config: ModelConfig) => void;
  onRunAnalysis?: (modelId: ModelType, prompt: string) => Promise<string>;
  presetPrompts?: {
    title: string;
    prompt: string;
    description?: string;
  }[];
}

const ModelInterface: React.FC<ModelInterfaceProps> = ({
  model,
  onSaveConfig,
  onRunAnalysis,
  presetPrompts = []
}) => {
  const [isConfiguring, setIsConfiguring] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<string | null>(null);
  const [editedConfig, setEditedConfig] = useState<ModelConfig>({ ...model });
  const [customPrompt, setCustomPrompt] = useState("");
  const [activeTab, setActiveTab] = useState("presets");
  const { toast } = useToast();

  const handleSaveConfig = () => {
    if (onSaveConfig) {
      onSaveConfig(editedConfig);
      setIsConfiguring(false);
      toast({
        title: "Configuration saved",
        description: `${model.name} settings have been updated.`,
      });
    }
  };

  const runAnalysis = async (prompt: string) => {
    if (!onRunAnalysis) return;
    
    setIsRunning(true);
    setProgress(0);
    setResult(null);
    
    // Simulate progress
    const interval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 95) {
          clearInterval(interval);
          return 95;
        }
        return prev + 5;
      });
    }, 300);
    
    try {
      const response = await onRunAnalysis(model.type, prompt);
      clearInterval(interval);
      setProgress(100);
      setResult(response);
      toast({
        title: "Analysis complete",
        description: `${model.name} has completed the requested analysis.`,
      });
    } catch (error) {
      clearInterval(interval);
      setProgress(0);
      toast({
        title: "Analysis failed",
        description: `There was an error processing your request: ${error instanceof Error ? error.message : 'Unknown error'}`,
        variant: "destructive",
      });
    } finally {
      setIsRunning(false);
    }
  };

  const renderConfigForm = () => (
    <div className="space-y-4 mt-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label htmlFor="api-key">API Key</Label>
          <Input
            id="api-key"
            type="password"
            placeholder="Enter API key"
            value={editedConfig.apiKey || ''}
            onChange={(e) => setEditedConfig({ ...editedConfig, apiKey: e.target.value })}
            className="bg-cyber-darker border-cyber-gray text-white"
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="endpoint">API Endpoint</Label>
          <Input
            id="endpoint"
            placeholder="Enter endpoint URL"
            value={editedConfig.endpoint || ''}
            onChange={(e) => setEditedConfig({ ...editedConfig, endpoint: e.target.value })}
            className="bg-cyber-darker border-cyber-gray text-white"
          />
        </div>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label htmlFor="max-tokens">Max Tokens</Label>
          <Input
            id="max-tokens"
            type="number"
            placeholder="Maximum tokens"
            value={editedConfig.maxTokens || 4096}
            onChange={(e) => setEditedConfig({ ...editedConfig, maxTokens: parseInt(e.target.value) })}
            className="bg-cyber-darker border-cyber-gray text-white"
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="temperature">Temperature</Label>
          <div className="flex items-center space-x-2">
            <Input
              id="temperature"
              type="range"
              min="0"
              max="1"
              step="0.1"
              value={editedConfig.temperature || 0.7}
              onChange={(e) => setEditedConfig({ ...editedConfig, temperature: parseFloat(e.target.value) })}
              className="bg-cyber-darker border-cyber-gray text-white"
            />
            <span className="text-white w-10">{editedConfig.temperature || 0.7}</span>
          </div>
        </div>
      </div>
      
      <div className="flex items-center space-x-2">
        <Switch
          id="auto-sync"
          checked={true}
          onCheckedChange={() => {}}
        />
        <Label htmlFor="auto-sync">Auto-sync with source data</Label>
      </div>
      
      <div className="flex justify-end space-x-2 mt-6">
        <Button variant="outline" onClick={() => setIsConfiguring(false)}>Cancel</Button>
        <Button onClick={handleSaveConfig}>Save Configuration</Button>
      </div>
    </div>
  );

  const renderStatusBadge = () => {
    switch (model.status) {
      case 'connected':
        return <Badge className="bg-cyber-success">Connected</Badge>;
      case 'disconnected':
        return <Badge variant="outline">Disconnected</Badge>;
      case 'error':
        return <Badge variant="destructive">Error</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };

  return (
    <Card className="bg-cyber-gray border-cyber-lightgray overflow-hidden mb-6">
      <CardHeader className="pb-2">
        <div className="flex justify-between items-center">
          <div className="flex items-center space-x-2">
            {model.icon || <Brain className="h-5 w-5" style={{ color: model.color || '#0EA5E9' }} />}
            <div>
              <CardTitle className="text-lg font-medium text-white">{model.name}</CardTitle>
              <CardDescription className="text-gray-400">{model.description}</CardDescription>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            {renderStatusBadge()}
            <Button
              variant="outline"
              size="sm"
              className="bg-cyber-darker text-xs"
              onClick={() => setIsConfiguring(!isConfiguring)}
            >
              Configure
            </Button>
          </div>
        </div>
      </CardHeader>
      
      <CardContent>
        {isConfiguring ? (
          renderConfigForm()
        ) : (
          <div>
            {model.lastSync && (
              <div className="text-xs text-gray-400 mb-4">
                Last synchronized: {model.lastSync}
              </div>
            )}
            
            <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
              <TabsList className="grid w-full grid-cols-2 h-10 bg-cyber-darker border border-cyber-gray">
                <TabsTrigger value="presets">Preset Prompts</TabsTrigger>
                <TabsTrigger value="custom">Custom Prompt</TabsTrigger>
              </TabsList>
              
              <TabsContent value="presets" className="pt-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {presetPrompts.map((preset, index) => (
                    <Card key={index} className="bg-cyber-darker border-cyber-gray hover:border-cyber-accent cursor-pointer transition-colors">
                      <CardHeader className="p-3 pb-2">
                        <CardTitle className="text-sm text-white">{preset.title}</CardTitle>
                      </CardHeader>
                      <CardContent className="p-3 pt-0">
                        <p className="text-xs text-gray-400">{preset.description || preset.prompt.substring(0, 100) + '...'}</p>
                      </CardContent>
                      <CardFooter className="p-3 pt-0 flex justify-end">
                        <Button 
                          size="sm" 
                          className="text-xs h-8"
                          onClick={() => runAnalysis(preset.prompt)}
                          disabled={isRunning}
                        >
                          Run Analysis
                        </Button>
                      </CardFooter>
                    </Card>
                  ))}
                </div>
              </TabsContent>
              
              <TabsContent value="custom" className="pt-4">
                <div className="space-y-4">
                  <Textarea
                    placeholder="Enter your custom prompt or query..."
                    value={customPrompt}
                    onChange={(e) => setCustomPrompt(e.target.value)}
                    className="bg-cyber-darker border-cyber-gray text-white min-h-[120px]"
                  />
                  <div className="flex justify-end">
                    <Button
                      onClick={() => runAnalysis(customPrompt)}
                      disabled={isRunning || !customPrompt.trim()}
                    >
                      {isRunning ? (
                        <>
                          <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                          Processing...
                        </>
                      ) : (
                        "Run Analysis"
                      )}
                    </Button>
                  </div>
                </div>
              </TabsContent>
            </Tabs>
            
            {isRunning && (
              <div className="mt-6 space-y-2">
                <div className="flex justify-between text-xs text-gray-400">
                  <span>Processing request...</span>
                  <span>{progress}%</span>
                </div>
                <Progress value={progress} className="h-1" />
              </div>
            )}
            
            {result && (
              <div className="mt-6">
                <Card className="bg-cyber-darker border-cyber-gray">
                  <CardHeader className="py-3 px-4">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-sm text-white">Analysis Result</CardTitle>
                      <div className="flex gap-2">
                        <Button variant="outline" size="icon" className="h-6 w-6">
                          <Save className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="py-3 px-4">
                    <div className="text-sm text-gray-300 whitespace-pre-line">
                      {result}
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default ModelInterface;
