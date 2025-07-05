import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { CircleDollarSign, UserRoundCheck, ShieldAlert, Bug } from 'lucide-react';
import CustomProgress from '@/components/ui/custom-progress';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Table,
  TableHeader,
  TableBody,
  TableFooter,
  TableHead,
  TableRow,
  TableCell,
  TableCaption,
} from "@/components/ui/table"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Calendar } from "@/components/ui/calendar"
import { CalendarIcon } from "lucide-react"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { cn } from "@/lib/utils"
import { format } from "date-fns"

interface Campaign {
  id: string;
  name: string;
  status: 'Active' | 'Inactive' | 'Completed';
  progress: number;
  budget: number;
  startDate: Date;
  endDate: Date;
  targetAudience: string;
  securityScore: number;
  vulnerabilities: number;
  agentsDeployed: number;
}

const CampaignsPage: React.FC = () => {
  const campaignsData: Campaign[] = [
    {
      id: 'CMP001',
      name: 'Phishing Awareness Training',
      status: 'Active',
      progress: 75,
      budget: 15000,
      startDate: new Date('2024-01-15'),
      endDate: new Date('2024-04-15'),
      targetAudience: 'All Employees',
      securityScore: 88,
      vulnerabilities: 5,
      agentsDeployed: 12,
    },
    {
      id: 'CMP002',
      name: 'Endpoint Security Enhancement',
      status: 'Active',
      progress: 40,
      budget: 30000,
      startDate: new Date('2024-02-01'),
      endDate: new Date('2024-05-01'),
      targetAudience: 'IT Department',
      securityScore: 72,
      vulnerabilities: 12,
      agentsDeployed: 25,
    },
    {
      id: 'CMP003',
      name: 'Network Intrusion Detection',
      status: 'Completed',
      progress: 100,
      budget: 22000,
      startDate: new Date('2023-11-01'),
      endDate: new Date('2024-01-31'),
      targetAudience: 'Security Team',
      securityScore: 92,
      vulnerabilities: 3,
      agentsDeployed: 18,
    },
    {
      id: 'CMP004',
      name: 'Data Loss Prevention Implementation',
      status: 'Active',
      progress: 60,
      budget: 28000,
      startDate: new Date('2024-03-01'),
      endDate: new Date('2024-06-01'),
      targetAudience: 'Compliance Department',
      securityScore: 78,
      vulnerabilities: 8,
      agentsDeployed: 20,
    },
    {
      id: 'CMP005',
      name: 'Incident Response Plan Update',
      status: 'Inactive',
      progress: 100,
      budget: 18000,
      startDate: new Date('2023-10-01'),
      endDate: new Date('2023-12-31'),
      targetAudience: 'Incident Response Team',
      securityScore: 95,
      vulnerabilities: 2,
      agentsDeployed: 15,
    },
  ];

  const [date, setDate] = React.useState<Date | undefined>(new Date())

  return (
      <div className="container mx-auto py-10">
        <div className="mb-8 flex items-center justify-between">
          <h1 className="text-3xl font-bold text-white">Campaigns</h1>
          <Button>Add Campaign</Button>
        </div>

        <div className="grid grid-cols-1 gap-6 mb-8">
          <Card className="bg-cyber-gray border-cyber-lightgray">
            <CardHeader>
              <CardTitle className="text-white">Active Campaigns Overview</CardTitle>
              <CardDescription className="text-gray-400">
                Summary of ongoing security campaigns
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="flex items-center space-x-4">
                  <CircleDollarSign className="h-8 w-8 text-cyber-accent" />
                  <div>
                    <h3 className="text-2xl font-semibold text-white">$83,000</h3>
                    <p className="text-sm text-gray-400">Total Budget</p>
                  </div>
                </div>
                <div className="flex items-center space-x-4">
                  <UserRoundCheck className="h-8 w-8 text-cyber-accent" />
                  <div>
                    <h3 className="text-2xl font-semibold text-white">4</h3>
                    <p className="text-sm text-gray-400">Active Campaigns</p>
                  </div>
                </div>
                <div className="flex items-center space-x-4">
                  <ShieldAlert className="h-8 w-8 text-cyber-accent" />
                  <div>
                    <h3 className="text-2xl font-semibold text-white">79</h3>
                    <p className="text-sm text-gray-400">Avg. Security Score</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 gap-6">
          <Card className="bg-cyber-gray border-cyber-lightgray">
            <CardHeader className="flex items-center justify-between">
              <CardTitle className="text-white">Campaign Progress</CardTitle>
              <Popover>
                <PopoverTrigger asChild>
                  <Button
                    variant={"ghost"}
                    className={cn(
                      "h-8 w-auto p-0 pl-2 text-left font-normal",
                      !date && "text-muted-foreground"
                    )}
                  >
                    <CalendarIcon className="mr-2 h-4 w-4" />
                    {date ? format(date, "PPP") : <span>Pick a date</span>}
                  </Button>
                </PopoverTrigger>
                <PopoverContent className="w-auto p-0" align="end">
                  <Calendar
                    mode="single"
                    selected={date}
                    onSelect={setDate}
                    disabled={(date) =>
                      date > new Date() || date < new Date("1900-01-01")
                    }
                    initialFocus
                  />
                </PopoverContent>
              </Popover>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[400px] w-full rounded-md border">
                <div className="space-y-4 pr-4">
                  {campaignsData.map((campaign) => (
                    <div key={campaign.id} className="space-y-2">
                      <div className="flex items-center justify-between">
                        <h4 className="text-lg font-semibold text-white">{campaign.name}</h4>
                        <Badge className="bg-blue-500 text-white">{campaign.status}</Badge>
                      </div>
                      <div className="flex items-center justify-between text-sm text-gray-400">
                        <span>Progress: {campaign.progress}%</span>
                        <span>Budget: ${campaign.budget}</span>
                      </div>
                      <CustomProgress value={campaign.progress} className="w-full" indicatorColor="#10b981" />
                      <div className="flex justify-between text-xs text-gray-500">
                        <span>Start Date: {campaign.startDate.toLocaleDateString()}</span>
                        <span>End Date: {campaign.endDate.toLocaleDateString()}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1">
          <Card className="bg-cyber-gray border-cyber-lightgray">
            <CardHeader>
              <CardTitle className="text-white">Campaign Details</CardTitle>
              <CardDescription className="text-gray-400">
                Detailed information about each campaign
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableCaption>A list of your recent campaigns.</TableCaption>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[100px]">ID</TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Progress</TableHead>
                    <TableHead>Budget</TableHead>
                    <TableHead>Start Date</TableHead>
                    <TableHead>End Date</TableHead>
                    <TableHead>Target Audience</TableHead>
                    <TableHead>Security Score</TableHead>
                    <TableHead>Vulnerabilities</TableHead>
                    <TableHead>Agents Deployed</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {campaignsData.map((campaign) => (
                    <TableRow key={campaign.id}>
                      <TableCell className="font-medium">{campaign.id}</TableCell>
                      <TableCell>{campaign.name}</TableCell>
                      <TableCell>{campaign.status}</TableCell>
                      <TableCell>
                        <div className="flex items-center">
                          <span>{campaign.progress}%</span>
                          <CustomProgress value={campaign.progress} className="w-32 ml-2" indicatorColor="#f59e0b" />
                        </div>
                      </TableCell>
                      <TableCell>${campaign.budget}</TableCell>
                      <TableCell>{campaign.startDate.toLocaleDateString()}</TableCell>
                      <TableCell>{campaign.endDate.toLocaleDateString()}</TableCell>
                      <TableCell>{campaign.targetAudience}</TableCell>
                      <TableCell>
                        <div className="flex items-center">
                          <span>{campaign.securityScore}</span>
                          {campaign.securityScore < 80 && (
                            <Bug className="ml-2 h-4 w-4 text-red-500" />
                          )}
                        </div>
                      </TableCell>
                      <TableCell>{campaign.vulnerabilities}</TableCell>
                      <TableCell>{campaign.agentsDeployed}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
                <TableFooter>
                  <TableRow>
                    <TableHead>Total</TableHead>
                    <TableHead colSpan={2}>
                      {campaignsData.length} Campaigns
                    </TableHead>
                    <TableHead colSpan={9} className="text-right">
                      Total Budget: ${campaignsData.reduce((acc, campaign) => acc + campaign.budget, 0)}
                    </TableHead>
                  </TableRow>
                </TableFooter>
              </Table>
            </CardContent>
          </Card>
        </div>
      </div>
  );
};

export default CampaignsPage;
