import React, { useState } from 'react';
import MainLayout from '@/components/layout/MainLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { Save, RefreshCw, Settings as SettingsIcon, Bell, Palette, Shield, Database } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

const SettingsPage: React.FC = () => {
  const { toast } = useToast();
  const [darkMode, setDarkMode] = useState(true);
  const [emailNotifications, setEmailNotifications] = useState(true);
  const [smsNotifications, setSmsNotifications] = useState(false);
  const [slackNotifications, setSlackNotifications] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState("5");

  const handleSaveSettings = () => {
    toast({
      title: "Settings saved",
      description: "Your settings have been updated successfully",
      variant: "default",
    });
  };

  const handleRefreshSettings = () => {
    // Reset to defaults
    setDarkMode(true);
    setEmailNotifications(true);
    setSmsNotifications(false);
    setSlackNotifications(true);
    setAutoRefresh(true);
    setRefreshInterval("5");
    
    toast({
      title: "Settings reset",
      description: "All settings have been reset to default values",
      variant: "default",
    });
  };

  return (
    <MainLayout>
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <h1 className="text-2xl font-bold text-white">Settings</h1>
          <div className="flex gap-2">
            <Button 
              variant="outline" 
              className="gap-2"
              onClick={handleRefreshSettings}
            >
              <RefreshCw className="h-4 w-4" />
              Reset
            </Button>
            <Button 
              variant="default" 
              className="gap-2"
              onClick={handleSaveSettings}
            >
              <Save className="h-4 w-4" />
              Save
            </Button>
          </div>
        </div>

        <Tabs defaultValue="general" className="w-full">
          <TabsList className="grid grid-cols-5 w-full max-w-2xl mb-6">
            <TabsTrigger value="general">General</TabsTrigger>
            <TabsTrigger value="notifications">Notifications</TabsTrigger>
            <TabsTrigger value="appearance">Appearance</TabsTrigger>
            <TabsTrigger value="security">Security</TabsTrigger>
            <TabsTrigger value="data">Data</TabsTrigger>
          </TabsList>

          <TabsContent value="general" className="space-y-4">
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardHeader>
                <CardTitle className="text-lg font-medium text-white flex items-center gap-2">
                  <SettingsIcon className="h-5 w-5 text-cyber-accent" />
                  General Settings
                </CardTitle>
                <CardDescription className="text-gray-400">
                  Configure general application settings and preferences
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <div>
                      <Label htmlFor="auto-refresh" className="text-white">Auto Refresh Dashboard</Label>
                      <p className="text-sm text-gray-400">Automatically refresh dashboard data</p>
                    </div>
                    <Switch 
                      id="auto-refresh" 
                      checked={autoRefresh} 
                      onCheckedChange={setAutoRefresh} 
                    />
                  </div>

                  {autoRefresh && (
                    <div className="flex items-center gap-4 ml-4 mt-2">
                      <Label htmlFor="refresh-interval" className="text-white whitespace-nowrap">
                        Refresh Interval
                      </Label>
                      <Select value={refreshInterval} onValueChange={setRefreshInterval}>
                        <SelectTrigger className="w-full max-w-[180px] bg-cyber-darker border-cyber-lightgray text-white">
                          <SelectValue placeholder="Select interval" />
                        </SelectTrigger>
                        <SelectContent className="bg-cyber-darker border-cyber-lightgray text-white">
                          <SelectItem value="1">1 minute</SelectItem>
                          <SelectItem value="5">5 minutes</SelectItem>
                          <SelectItem value="10">10 minutes</SelectItem>
                          <SelectItem value="15">15 minutes</SelectItem>
                          <SelectItem value="30">30 minutes</SelectItem>
                          <SelectItem value="60">1 hour</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  )}
                </div>

                <Separator className="bg-cyber-lightgray" />

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <Label htmlFor="api-key" className="text-white">API Key</Label>
                    <Input 
                      id="api-key" 
                      type="password" 
                      className="mt-1 bg-cyber-darker border-cyber-lightgray text-white" 
                      value="••••••••••••••••"
                      readOnly
                    />
                    <p className="text-xs text-gray-400 mt-1">Used for integration with external systems</p>
                  </div>
                  <div>
                    <Label htmlFor="timezone" className="text-white">Timezone</Label>
                    <Select defaultValue="utc">
                      <SelectTrigger className="mt-1 bg-cyber-darker border-cyber-lightgray text-white">
                        <SelectValue placeholder="Select timezone" />
                      </SelectTrigger>
                      <SelectContent className="bg-cyber-darker border-cyber-lightgray text-white">
                        <SelectItem value="utc">UTC</SelectItem>
                        <SelectItem value="local">Local Browser Time</SelectItem>
                        <SelectItem value="et">Eastern Time (ET)</SelectItem>
                        <SelectItem value="pt">Pacific Time (PT)</SelectItem>
                        <SelectItem value="gmt">Greenwich Mean Time (GMT)</SelectItem>
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-gray-400 mt-1">Timezone for displaying dates and times</p>
                  </div>
                </div>

                <Separator className="bg-cyber-lightgray" />

                <div>
                  <Label htmlFor="default-page" className="text-white">Default Landing Page</Label>
                  <Select defaultValue="dashboard">
                    <SelectTrigger className="mt-1 bg-cyber-darker border-cyber-lightgray text-white">
                      <SelectValue placeholder="Select default page" />
                    </SelectTrigger>
                    <SelectContent className="bg-cyber-darker border-cyber-lightgray text-white">
                      <SelectItem value="dashboard">Dashboard</SelectItem>
                      <SelectItem value="alerts">Alerts</SelectItem>
                      <SelectItem value="campaigns">Campaigns</SelectItem>
                      <SelectItem value="agents">Agents</SelectItem>
                      <SelectItem value="techniques">Techniques</SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-gray-400 mt-1">The page that loads when you first open the application</p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="notifications" className="space-y-4">
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardHeader>
                <CardTitle className="text-lg font-medium text-white flex items-center gap-2">
                  <Bell className="h-5 w-5 text-cyber-accent" />
                  Notification Settings
                </CardTitle>
                <CardDescription className="text-gray-400">
                  Configure how and when you receive alerts and notifications
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <div>
                      <Label htmlFor="email-notifications" className="text-white">Email Notifications</Label>
                      <p className="text-sm text-gray-400">Receive notifications via email</p>
                    </div>
                    <Switch 
                      id="email-notifications" 
                      checked={emailNotifications} 
                      onCheckedChange={setEmailNotifications} 
                    />
                  </div>

                  {emailNotifications && (
                    <div className="ml-4 mt-2 space-y-2">
                      <div className="flex items-center gap-4">
                        <Label htmlFor="email-address" className="text-white whitespace-nowrap">
                          Email Address
                        </Label>
                        <Input 
                          id="email-address" 
                          type="email" 
                          className="w-full max-w-[300px] bg-cyber-darker border-cyber-lightgray text-white" 
                          placeholder="user@example.com"
                        />
                      </div>
                      <div>
                        <Label className="text-white">Email Alert Levels</Label>
                        <div className="grid grid-cols-2 gap-2 mt-2">
                          <div className="flex items-center gap-2">
                            <Switch id="email-critical" defaultChecked />
                            <Label htmlFor="email-critical" className="text-white">Critical</Label>
                          </div>
                          <div className="flex items-center gap-2">
                            <Switch id="email-high" defaultChecked />
                            <Label htmlFor="email-high" className="text-white">High</Label>
                          </div>
                          <div className="flex items-center gap-2">
                            <Switch id="email-medium" />
                            <Label htmlFor="email-medium" className="text-white">Medium</Label>
                          </div>
                          <div className="flex items-center gap-2">
                            <Switch id="email-low" />
                            <Label htmlFor="email-low" className="text-white">Low</Label>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  <Separator className="bg-cyber-lightgray" />

                  <div className="flex justify-between items-center">
                    <div>
                      <Label htmlFor="sms-notifications" className="text-white">SMS Notifications</Label>
                      <p className="text-sm text-gray-400">Receive notifications via SMS</p>
                    </div>
                    <Switch 
                      id="sms-notifications" 
                      checked={smsNotifications} 
                      onCheckedChange={setSmsNotifications} 
                    />
                  </div>

                  {smsNotifications && (
                    <div className="ml-4 mt-2">
                      <div className="flex items-center gap-4">
                        <Label htmlFor="phone-number" className="text-white whitespace-nowrap">
                          Phone Number
                        </Label>
                        <Input 
                          id="phone-number" 
                          type="tel" 
                          className="w-full max-w-[300px] bg-cyber-darker border-cyber-lightgray text-white" 
                          placeholder="+1 (555) 123-4567"
                        />
                      </div>
                    </div>
                  )}

                  <Separator className="bg-cyber-lightgray" />

                  <div className="flex justify-between items-center">
                    <div>
                      <Label htmlFor="slack-notifications" className="text-white">Slack Notifications</Label>
                      <p className="text-sm text-gray-400">Receive notifications via Slack</p>
                    </div>
                    <Switch 
                      id="slack-notifications" 
                      checked={slackNotifications} 
                      onCheckedChange={setSlackNotifications} 
                    />
                  </div>

                  {slackNotifications && (
                    <div className="ml-4 mt-2 space-y-2">
                      <div className="flex items-center gap-4">
                        <Label htmlFor="slack-webhook" className="text-white whitespace-nowrap">
                          Webhook URL
                        </Label>
                        <Input 
                          id="slack-webhook" 
                          type="text" 
                          className="w-full max-w-[300px] bg-cyber-darker border-cyber-lightgray text-white" 
                          placeholder="https://hooks.slack.com/services/..."
                        />
                      </div>
                      <div className="flex items-center gap-4">
                        <Label htmlFor="slack-channel" className="text-white whitespace-nowrap">
                          Channel
                        </Label>
                        <Input 
                          id="slack-channel" 
                          type="text" 
                          className="w-full max-w-[300px] bg-cyber-darker border-cyber-lightgray text-white" 
                          placeholder="#security-alerts"
                        />
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="appearance" className="space-y-4">
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardHeader>
                <CardTitle className="text-lg font-medium text-white flex items-center gap-2">
                  <Palette className="h-5 w-5 text-cyber-accent" />
                  Appearance Settings
                </CardTitle>
                <CardDescription className="text-gray-400">
                  Customize the look and feel of the application
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <div>
                      <Label htmlFor="dark-mode" className="text-white">Dark Mode</Label>
                      <p className="text-sm text-gray-400">Use dark theme for the application</p>
                    </div>
                    <Switch 
                      id="dark-mode" 
                      checked={darkMode} 
                      onCheckedChange={setDarkMode} 
                    />
                  </div>

                  <Separator className="bg-cyber-lightgray" />

                  <div>
                    <Label htmlFor="theme-color" className="text-white">Accent Color</Label>
                    <div className="grid grid-cols-5 gap-2 mt-2">
                      <div className="w-10 h-10 rounded-full bg-blue-500 cursor-pointer border-2 border-white"></div>
                      <div className="w-10 h-10 rounded-full bg-purple-500 cursor-pointer"></div>
                      <div className="w-10 h-10 rounded-full bg-green-500 cursor-pointer"></div>
                      <div className="w-10 h-10 rounded-full bg-red-500 cursor-pointer"></div>
                      <div className="w-10 h-10 rounded-full bg-yellow-500 cursor-pointer"></div>
                    </div>
                    <p className="text-xs text-gray-400 mt-1">Highlight color for important elements</p>
                  </div>

                  <Separator className="bg-cyber-lightgray" />

                  <div>
                    <Label htmlFor="font-size" className="text-white">Font Size</Label>
                    <Select defaultValue="medium">
                      <SelectTrigger className="mt-1 bg-cyber-darker border-cyber-lightgray text-white">
                        <SelectValue placeholder="Select font size" />
                      </SelectTrigger>
                      <SelectContent className="bg-cyber-darker border-cyber-lightgray text-white">
                        <SelectItem value="small">Small</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="large">Large</SelectItem>
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-gray-400 mt-1">Default text size for the application</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="security" className="space-y-4">
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardHeader>
                <CardTitle className="text-lg font-medium text-white flex items-center gap-2">
                  <Shield className="h-5 w-5 text-cyber-accent" />
                  Security Settings
                </CardTitle>
                <CardDescription className="text-gray-400">
                  Configure security preferences and access controls
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <div>
                      <Label htmlFor="two-factor" className="text-white">Two-Factor Authentication</Label>
                      <p className="text-sm text-gray-400">Require 2FA for account access</p>
                    </div>
                    <Switch id="two-factor" defaultChecked />
                  </div>

                  <Separator className="bg-cyber-lightgray" />

                  <div className="flex justify-between items-center">
                    <div>
                      <Label htmlFor="session-timeout" className="text-white">Session Timeout</Label>
                      <p className="text-sm text-gray-400">Automatically log out after inactivity</p>
                    </div>
                    <Select defaultValue="30">
                      <SelectTrigger className="w-[180px] bg-cyber-darker border-cyber-lightgray text-white">
                        <SelectValue placeholder="Select timeout" />
                      </SelectTrigger>
                      <SelectContent className="bg-cyber-darker border-cyber-lightgray text-white">
                        <SelectItem value="15">15 minutes</SelectItem>
                        <SelectItem value="30">30 minutes</SelectItem>
                        <SelectItem value="60">1 hour</SelectItem>
                        <SelectItem value="120">2 hours</SelectItem>
                        <SelectItem value="never">Never</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <Separator className="bg-cyber-lightgray" />

                  <div>
                    <Label className="text-white">API Access Control</Label>
                    <div className="grid grid-cols-2 gap-2 mt-2">
                      <div className="flex items-center gap-2">
                        <Switch id="api-read" defaultChecked />
                        <Label htmlFor="api-read" className="text-white">Read Access</Label>
                      </div>
                      <div className="flex items-center gap-2">
                        <Switch id="api-write" defaultChecked />
                        <Label htmlFor="api-write" className="text-white">Write Access</Label>
                      </div>
                      <div className="flex items-center gap-2">
                        <Switch id="api-delete" />
                        <Label htmlFor="api-delete" className="text-white">Delete Access</Label>
                      </div>
                      <div className="flex items-center gap-2">
                        <Switch id="api-admin" />
                        <Label htmlFor="api-admin" className="text-white">Admin Access</Label>
                      </div>
                    </div>
                    <p className="text-xs text-gray-400 mt-1">Control what operations API keys can perform</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="data" className="space-y-4">
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardHeader>
                <CardTitle className="text-lg font-medium text-white flex items-center gap-2">
                  <Database className="h-5 w-5 text-cyber-accent" />
                  Data Management
                </CardTitle>
                <CardDescription className="text-gray-400">
                  Manage application data and storage settings
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <div>
                      <Label htmlFor="auto-backup" className="text-white">Automatic Backups</Label>
                      <p className="text-sm text-gray-400">Schedule regular data backups</p>
                    </div>
                    <Switch id="auto-backup" defaultChecked />
                  </div>

                  <div className="flex justify-between items-center">
                    <div>
                      <Label htmlFor="backup-frequency" className="text-white">Backup Frequency</Label>
                    </div>
                    <Select defaultValue="daily">
                      <SelectTrigger className="w-[180px] bg-cyber-darker border-cyber-lightgray text-white">
                        <SelectValue placeholder="Select frequency" />
                      </SelectTrigger>
                      <SelectContent className="bg-cyber-darker border-cyber-lightgray text-white">
                        <SelectItem value="hourly">Hourly</SelectItem>
                        <SelectItem value="daily">Daily</SelectItem>
                        <SelectItem value="weekly">Weekly</SelectItem>
                        <SelectItem value="monthly">Monthly</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <Separator className="bg-cyber-lightgray" />

                  <div className="flex justify-between items-center">
                    <div>
                      <Label htmlFor="data-retention" className="text-white">Data Retention Period</Label>
                      <p className="text-sm text-gray-400">How long to keep historical data</p>
                    </div>
                    <Select defaultValue="180">
                      <SelectTrigger className="w-[180px] bg-cyber-darker border-cyber-lightgray text-white">
                        <SelectValue placeholder="Select period" />
                      </SelectTrigger>
                      <SelectContent className="bg-cyber-darker border-cyber-lightgray text-white">
                        <SelectItem value="30">30 days</SelectItem>
                        <SelectItem value="90">90 days</SelectItem>
                        <SelectItem value="180">6 months</SelectItem>
                        <SelectItem value="365">1 year</SelectItem>
                        <SelectItem value="forever">Forever</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <Separator className="bg-cyber-lightgray" />
                  
                  <div>
                    <h3 className="text-white font-medium mb-2">Clear Data</h3>
                    <p className="text-sm text-gray-400 mb-4">
                      Remove all demonstration data from the system. This action cannot be undone.
                    </p>
                    <Button 
                      variant="destructive" 
                      className="gap-2"
                    >
                      Remove All Dummy Data
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  );
};

export default SettingsPage;
