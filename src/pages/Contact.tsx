
import MainLayout from "@/components/layout/MainLayout";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Linkedin, Github, ExternalLink, Mail, User, MessageSquare } from "lucide-react";

const Contact = () => {
  return (
    <MainLayout>
      <div className="container mx-auto py-6 space-y-6">
        <h1 className="text-3xl font-bold text-white mb-6">Contact</h1>
        
        <div className="grid gap-6 md:grid-cols-2">
          {/* Profile Card */}
          <Card className="bg-cyber-darker border-cyber-gray text-white">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <User className="h-5 w-5 text-cyber-accent" />
                Ahmed Hassan
              </CardTitle>
              <CardDescription className="text-gray-300">
                Security Operations Center Specialist
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-gray-300">
                Experienced SOC specialist with expertise in security operations, threat intelligence, 
                and incident response. Focused on building robust security solutions.
              </p>
              
              <div className="bg-cyber-gray p-4 rounded-md">
                <h3 className="text-cyber-accent font-semibold mb-2">Areas of Expertise</h3>
                <ul className="list-disc list-inside text-gray-300 space-y-1">
                  <li>Security Operations Center (SOC) Management</li>
                  <li>Threat Intelligence & Analysis</li>
                  <li>SIEM Implementation & Configuration</li>
                  <li>Incident Response</li>
                  <li>Security Tool Integration</li>
                </ul>
              </div>
            </CardContent>
            <CardFooter className="border-t border-cyber-gray pt-4">
              <div className="flex flex-wrap gap-3">
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="bg-cyber-gray hover:bg-cyber-accent text-white"
                  onClick={() => window.open("mailto:contact@example.com")}
                >
                  <Mail className="mr-2 h-4 w-4" />
                  Contact Me
                </Button>
              </div>
            </CardFooter>
          </Card>
          
          {/* Professional Profiles Card */}
          <Card className="bg-cyber-darker border-cyber-gray text-white">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <MessageSquare className="h-5 w-5 text-cyber-accent" />
                Connect With Me
              </CardTitle>
              <CardDescription className="text-gray-300">
                Find me on these professional platforms
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-4">
                {/* Freelancer */}
                <div className="flex items-start gap-4 p-3 bg-cyber-gray rounded-md transition-all hover:scale-[1.02]">
                  <ExternalLink className="h-10 w-10 text-white bg-blue-600 p-2 rounded-md" />
                  <div>
                    <h3 className="font-medium text-white">Freelancer</h3>
                    <p className="text-sm text-gray-300 mb-2">View my freelancing profile and hire me for projects</p>
                    <Button 
                      variant="outline" 
                      size="sm" 
                      className="text-xs bg-cyber-dark hover:bg-cyber-accent"
                      onClick={() => window.open("https://www.freelancer.com/u/ahmedhassan52", "_blank")}
                    >
                      <ExternalLink className="mr-2 h-3 w-3" />
                      View Profile
                    </Button>
                  </div>
                </div>
                
                {/* LinkedIn */}
                <div className="flex items-start gap-4 p-3 bg-cyber-gray rounded-md transition-all hover:scale-[1.02]">
                  <Linkedin className="h-10 w-10 text-white bg-[#0A66C2] p-2 rounded-md" />
                  <div>
                    <h3 className="font-medium text-white">LinkedIn</h3>
                    <p className="text-sm text-gray-300 mb-2">Connect with me professionally on LinkedIn</p>
                    <Button 
                      variant="outline" 
                      size="sm" 
                      className="text-xs bg-cyber-dark hover:bg-cyber-accent"
                      onClick={() => window.open("https://www.linkedin.com/in/ahmed-hassan-f11/", "_blank")}
                    >
                      <ExternalLink className="mr-2 h-3 w-3" />
                      View Profile
                    </Button>
                  </div>
                </div>
                
                {/* GitHub */}
                <div className="flex items-start gap-4 p-3 bg-cyber-gray rounded-md transition-all hover:scale-[1.02]">
                  <Github className="h-10 w-10 text-white bg-[#24292e] p-2 rounded-md" />
                  <div>
                    <h3 className="font-medium text-white">GitHub</h3>
                    <p className="text-sm text-gray-300 mb-2">Check out my projects and contributions</p>
                    <Button 
                      variant="outline" 
                      size="sm" 
                      className="text-xs bg-cyber-dark hover:bg-cyber-accent"
                      onClick={() => window.open("https://github.com/AAH20", "_blank")}
                    >
                      <ExternalLink className="mr-2 h-3 w-3" />
                      View Profile
                    </Button>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </MainLayout>
  );
};

export default Contact;
