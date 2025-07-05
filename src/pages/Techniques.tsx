import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Search, Filter, Info, ExternalLink, Zap, Shield, RefreshCw, FileText, AlertTriangle, Target, Database } from 'lucide-react';
import { useToast } from "@/hooks/use-toast";
import { apiService } from '@/services/api';

// MITRE ATT&CK Data Types
interface Technique {
  id: string;
  name: string;
  description: string;
  tactic: string;
  platforms: string[];
  dataSource: string[];
  procedure: string;
  detection: string;
  mitigation: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

interface TacticGroup {
  name: string;
  techniques: Technique[];
}

// Fetch techniques from our database-driven API
const fetchTechniques = async (): Promise<TacticGroup[]> => {
  try {
    console.log('Fetching MITRE ATT&CK techniques from database...');
    
    const response = await apiService.get('/api/security-events/techniques');
    
    if (response.data?.success) {
      // Transform database response into TacticGroup format
      const techniques = response.data.data || [];
      
      // Group techniques by tactic
      const tacticGroups: { [key: string]: Technique[] } = {};
      
      techniques.forEach((technique: any) => {
        const tactic = technique.mitre_tactic || 'Unknown';
        if (!tacticGroups[tactic]) {
          tacticGroups[tactic] = [];
        }
        
        tacticGroups[tactic].push({
          id: technique.mitre_technique_id || technique.id,
          name: technique.technique_name || technique.name,
          description: technique.description || `Analysis of ${technique.technique_name || 'security technique'}`,
          tactic,
          platforms: technique.platforms ? technique.platforms.split(',') : ['Multiple'],
          dataSource: technique.data_sources ? technique.data_sources.split(',') : ['Security Events'],
          procedure: technique.procedure || `Detected through security monitoring and analysis`,
          detection: technique.detection_methods || `Monitor for indicators related to ${technique.technique_name}`,
          mitigation: technique.mitigation_steps || `Implement security controls to prevent ${technique.technique_name}`,
          severity: technique.severity || 'medium'
        });
      });
      
      // Convert to TacticGroup array
      return Object.entries(tacticGroups).map(([name, techniques]) => ({
        name,
        techniques
      }));
    }
    
    // Fallback if no database data
    return [];
    
  } catch (error) {
    console.error('Failed to fetch techniques from database:', error);
    throw error;
  }
};

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case 'critical': return 'bg-red-600 hover:bg-red-700';
    case 'high': return 'bg-orange-500 hover:bg-orange-600';
    case 'medium': return 'bg-yellow-500 hover:bg-yellow-600';
    case 'low': return 'bg-blue-500 hover:bg-blue-600';
    default: return 'bg-slate-700 hover:bg-slate-600';
  }
};

const TechniquesPage: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedTactic, setSelectedTactic] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [tacticsData, setTacticsData] = useState<TacticGroup[] | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadTechniques = async () => {
      try {
        setIsLoading(true);
        setError(null);
        const data = await fetchTechniques();
        setTacticsData(data);
      } catch (err) {
        setError('Failed to load techniques');
        console.error('Error loading techniques:', err);
      } finally {
        setIsLoading(false);
      }
    };

    loadTechniques();
  }, []);

  const filteredTechniques = React.useMemo(() => {
    if (!tacticsData) return [];
    
    let allTechniques: Technique[] = [];
    tacticsData.forEach(tactic => {
      allTechniques = [...allTechniques, ...tactic.techniques];
    });

    return allTechniques.filter(technique => {
      const matchesSearch = technique.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          technique.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          technique.id.toLowerCase().includes(searchTerm.toLowerCase());
      
      const matchesTactic = selectedTactic === 'all' || technique.tactic === selectedTactic;
      const matchesSeverity = selectedSeverity === 'all' || technique.severity === selectedSeverity;
      
      return matchesSearch && matchesTactic && matchesSeverity;
    });
  }, [tacticsData, searchTerm, selectedTactic, selectedSeverity]);

  const getAllTactics = () => {
    if (!tacticsData) return [];
    return tacticsData.map(tactic => tactic.name);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96 bg-slate-900 min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-slate-400">Loading MITRE ATT&CK techniques...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-96 bg-slate-900 min-h-screen">
        <div className="text-center">
          <p className="text-red-400 text-lg">Error loading techniques</p>
          <p className="text-slate-400">Please try again later</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 bg-slate-900 min-h-screen p-6">
      <div className="flex items-center gap-2">
        <Zap className="h-6 w-6 text-blue-400" />
        <h1 className="text-2xl font-bold text-white">MITRE ATT&CK Techniques</h1>
      </div>
      
      <p className="text-slate-400">
        Explore and understand adversary tactics, techniques, and procedures based on real-world observations.
      </p>

      {/* Search and Filter Section */}
      <Card className="bg-slate-800 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Search className="h-5 w-5" />
            Search & Filter
          </CardTitle>
          <CardDescription className="text-slate-400">
            Find specific techniques and filter by tactic or severity
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium text-white">Search Techniques</label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400 h-4 w-4" />
                <Input
                  placeholder="Search by name, ID, or description..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10 bg-slate-700 border-slate-600 text-white placeholder:text-slate-400"
                />
              </div>
            </div>
            
            <div className="space-y-2">
              <label className="text-sm font-medium text-white">Filter by Tactic</label>
              <select
                value={selectedTactic}
                onChange={(e) => setSelectedTactic(e.target.value)}
                className="w-full p-2 rounded-md border bg-slate-700 border-slate-600 text-white focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Tactics</option>
                {getAllTactics().map(tactic => (
                  <option key={tactic} value={tactic}>{tactic}</option>
                ))}
              </select>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-white">Filter by Severity</label>
              <select
                value={selectedSeverity}
                onChange={(e) => setSelectedSeverity(e.target.value)}
                className="w-full p-2 rounded-md border bg-slate-700 border-slate-600 text-white focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Severities</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Results Summary */}
      <div className="flex items-center justify-between">
        <p className="text-slate-400">
          Showing {filteredTechniques.length} techniques 
          {searchTerm && ` matching "${searchTerm}"`}
          {selectedTactic !== 'all' && ` in ${selectedTactic}`}
          {selectedSeverity !== 'all' && ` with ${selectedSeverity} severity`}
        </p>
        <Badge variant="outline" className="border-slate-600 text-slate-300">
          {filteredTechniques.length} results
        </Badge>
      </div>

      {/* Techniques Grid */}
      <div className="grid gap-6">
        {filteredTechniques.length === 0 ? (
          <Card className="bg-slate-800 border-slate-700">
            <CardContent className="p-8 text-center">
              <Info className="h-12 w-12 text-slate-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-white mb-2">No techniques found</h3>
              <p className="text-slate-400">Try adjusting your search criteria or filters</p>
            </CardContent>
          </Card>
        ) : (
          filteredTechniques.map((technique) => (
            <Card key={technique.id} className="bg-slate-800 border-slate-700 hover:border-slate-600 transition-colors">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="font-mono border-slate-600 text-slate-300">
                        {technique.id}
                      </Badge>
                      <Badge className={getSeverityColor(technique.severity)}>
                        {technique.severity.toUpperCase()}
                      </Badge>
                      <Badge variant="secondary" className="bg-slate-700 text-slate-300">
                        {technique.tactic}
                      </Badge>
                    </div>
                    <CardTitle className="text-white">{technique.name}</CardTitle>
                  </div>
                  <ExternalLink className="h-5 w-5 text-slate-400" />
                </div>
                <CardDescription className="text-slate-400">
                  {technique.description}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="procedure" className="w-full">
                  <TabsList className="grid w-full grid-cols-4 bg-slate-700">
                    <TabsTrigger value="procedure" className="data-[state=active]:bg-slate-600 text-slate-300">Procedure</TabsTrigger>
                    <TabsTrigger value="detection" className="data-[state=active]:bg-slate-600 text-slate-300">Detection</TabsTrigger>
                    <TabsTrigger value="mitigation" className="data-[state=active]:bg-slate-600 text-slate-300">Mitigation</TabsTrigger>
                    <TabsTrigger value="details" className="data-[state=active]:bg-slate-600 text-slate-300">Details</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="procedure" className="mt-4">
                    <div className="space-y-3">
                      <h4 className="font-medium text-white">APT Usage Examples</h4>
                      <p className="text-sm text-slate-300 leading-relaxed">{technique.procedure}</p>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="detection" className="mt-4">
                    <div className="space-y-3">
                      <h4 className="font-medium text-white">Detection Methods</h4>
                      <p className="text-sm text-slate-300 leading-relaxed">{technique.detection}</p>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="mitigation" className="mt-4">
                    <div className="space-y-3">
                      <h4 className="font-medium text-white">Mitigation Strategies</h4>
                      <p className="text-sm text-slate-300 leading-relaxed">{technique.mitigation}</p>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="details" className="mt-4">
                    <div className="space-y-4">
                      <div>
                        <h4 className="font-medium text-white mb-2">Platforms</h4>
                        <div className="flex flex-wrap gap-2">
                          {technique.platforms.map((platform) => (
                            <Badge key={platform} variant="outline" className="border-slate-600 text-slate-300">
                              {platform}
                            </Badge>
                          ))}
                        </div>
                      </div>
                      
                      <div>
                        <h4 className="font-medium text-white mb-2">Data Sources</h4>
                        <div className="flex flex-wrap gap-2">
                          {technique.dataSource.map((source) => (
                            <Badge key={source} variant="secondary" className="bg-slate-700 text-slate-300">
                              {source}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );
};

export default TechniquesPage;
