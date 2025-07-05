
import React, { useState } from 'react';
import { 
  Tabs, 
  TabsContent, 
  TabsList, 
  TabsTrigger 
} from '@/components/ui/tabs';
import { 
  Card, 
  CardContent, 
  CardDescription, 
  CardHeader, 
  CardTitle 
} from '@/components/ui/card';
import { 
  Shield, 
  FileCheck, 
  Lock, 
  FileLock, 
  FileSearch,
  CheckCircle2,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';

// Define the compliance frameworks with enhanced control details
const complianceFrameworks = [
  {
    id: 'iso27001',
    name: 'ISO 27001',
    description: 'Information Security Management System (ISMS) standard focusing on protecting the confidentiality, integrity, and availability of information.',
    status: 'Certified',
    lastAudit: '2023-10-15',
    nextAudit: '2024-10-15',
    icon: Shield,
    controls: [
      { 
        id: 'A.5', 
        name: 'Information Security Policies', 
        status: 'Compliant',
        details: 'Documented and approved information security policies that are communicated to all employees and relevant external parties. Regular reviews are conducted and management demonstrates commitment to information security.'
      },
      { 
        id: 'A.6', 
        name: 'Organization of Information Security', 
        status: 'Compliant',
        details: 'Clearly defined information security roles and responsibilities. Segregation of duties implemented to reduce risk of unauthorized access. Appropriate contacts with authorities and special interest groups maintained.'
      },
      { 
        id: 'A.7', 
        name: 'Human Resource Security', 
        status: 'Compliant',
        details: 'Background verification checks conducted for all candidates. Employment agreements include information security responsibilities. Disciplinary process established for security violations. Termination procedures include removal of access rights.'
      },
      { 
        id: 'A.8', 
        name: 'Asset Management', 
        status: 'Compliant',
        details: 'Inventory of assets maintained with clearly identified owners. Information classification scheme implemented. Media handling procedures established with secure disposal methods for sensitive information.'
      },
      { 
        id: 'A.9', 
        name: 'Access Control', 
        status: 'Minor Finding',
        details: 'Access control policy documented but 3 privileged accounts found without recent reviews. Formal user access provisioning process implemented. Regular access rights review scheduled but last quarter\'s review was delayed by 2 weeks.'
      },
      { 
        id: 'A.10', 
        name: 'Cryptography', 
        status: 'Compliant',
        details: 'Policy on the use of cryptographic controls established. Key management system implemented for encryption keys. All sensitive data in transit and at rest is encrypted using industry-standard encryption algorithms.'
      }
    ]
  },
  {
    id: 'soc2',
    name: 'SOC 2',
    description: 'Service Organization Control report focusing on Trust Service Criteria: security, availability, processing integrity, confidentiality, and privacy.',
    status: 'Type II Compliant',
    lastAudit: '2023-11-20',
    nextAudit: '2024-11-20',
    icon: FileCheck,
    controls: [
      { 
        id: 'CC1.0', 
        name: 'Control Environment', 
        status: 'Compliant',
        details: 'Board oversight of information security program documented. Code of conduct in place and acknowledged by all employees. Organizational structure with clear reporting lines established. Annual performance reviews include security responsibilities.'
      },
      { 
        id: 'CC2.0', 
        name: 'Communication and Information', 
        status: 'Compliant',
        details: 'Internal communication channels established for security updates. Customer communication protocols documented. System descriptions maintained with current processing boundaries. Change management process includes security impact assessment.'
      },
      { 
        id: 'CC3.0', 
        name: 'Risk Assessment', 
        status: 'Minor Finding',
        details: 'Risk assessment methodology documented but the latest vendor risk assessment was completed 2 months behind schedule. Business impact analysis conducted annually. Vulnerability management program in place but needs more frequent scans.'
      },
      { 
        id: 'CC4.0', 
        name: 'Monitoring Activities', 
        status: 'Compliant',
        details: 'Continuous monitoring tools deployed for network and system activity. Security information and event management (SIEM) solution implemented. Internal audit program evaluates control effectiveness quarterly.'
      },
      { 
        id: 'CC5.0', 
        name: 'Control Activities', 
        status: 'Compliant',
        details: 'Control selection based on risk assessment results. System development lifecycle includes security requirements and testing. Change management process includes security impact assessment and approval workflows.'
      },
      { 
        id: 'CC6.0', 
        name: 'Logical and Physical Access', 
        status: 'Compliant',
        details: 'Multi-factor authentication required for all privileged access. Least privilege principles implemented. Physical access controls at data centers include biometric authentication and 24/7 monitoring. System configurations hardened according to CIS benchmarks.'
      }
    ]
  },
  {
    id: 'gdpr',
    name: 'GDPR',
    description: 'General Data Protection Regulation for data protection and privacy in the European Union and the European Economic Area.',
    status: 'Compliant',
    lastAudit: '2024-01-10',
    nextAudit: '2025-01-10',
    icon: Lock,
    controls: [
      { 
        id: 'Art.5', 
        name: 'Principles for Processing', 
        status: 'Compliant',
        details: 'Personal data processed lawfully, fairly and transparently. Data collected for specified, explicit and legitimate purposes. Data minimization practices implemented to ensure only necessary data is collected. Accuracy of data maintained with regular review cycles.'
      },
      { 
        id: 'Art.6', 
        name: 'Lawfulness of Processing', 
        status: 'Compliant',
        details: 'Legal basis established for all data processing activities. Consent mechanisms implemented where required. Legitimate interest assessments documented. Contract requirements for data processing identified and fulfilled.'
      },
      { 
        id: 'Art.7', 
        name: 'Conditions for Consent', 
        status: 'Compliant',
        details: 'Consent obtained through clear affirmative action. Consent forms provide easy-to-understand information. Consent withdrawal mechanism implemented and documented. Parental consent verification for children\'s data established.'
      },
      { 
        id: 'Art.12-23', 
        name: 'Data Subject Rights', 
        status: 'Minor Finding',
        details: 'Procedures established for handling data subject requests, but response time exceeded 30 days in 2 instances. Right to erasure ("right to be forgotten") technically implemented but process documentation needs update. Subject access request tracking system implemented.'
      },
      { 
        id: 'Art.25', 
        name: 'Data Protection by Design', 
        status: 'Compliant',
        details: 'Privacy impact assessments conducted for new systems and processes. Data protection considerations integrated into project management methodology. Default privacy settings configured to minimize data collection and retention.'
      },
      { 
        id: 'Art.30', 
        name: 'Records of Processing', 
        status: 'Compliant',
        details: 'Records of processing activities maintained with categories of data subjects, purposes, recipients, and safeguards. Regular reviews of the processing records conducted. Records available to supervisory authorities upon request.'
      }
    ]
  },
  {
    id: 'hipaa',
    name: 'HIPAA',
    description: 'Health Insurance Portability and Accountability Act for protecting sensitive patient health information from disclosure without consent.',
    status: 'Compliant',
    lastAudit: '2023-09-05',
    nextAudit: '2024-09-05',
    icon: FileLock,
    controls: [
      { 
        id: '164.308', 
        name: 'Administrative Safeguards', 
        status: 'Compliant',
        details: 'Security management process established with risk analysis and risk management procedures. Security officer appointed with documented responsibilities. Workforce security procedures include authorization and supervision. Security awareness training conducted annually for all staff.'
      },
      { 
        id: '164.310', 
        name: 'Physical Safeguards', 
        status: 'Compliant',
        details: 'Facility access controls implemented with documented contingency operations. Device and media controls include disposal procedures and media re-use policies. Workstations secured in areas with restricted access. Mobile device policies established and enforced.'
      },
      { 
        id: '164.312', 
        name: 'Technical Safeguards', 
        status: 'Compliant',
        details: 'Unique user identification enforced for all systems containing PHI. Emergency access procedures tested quarterly. Automatic logoff implemented for all workstations. Data encryption used for transmission security of PHI.'
      },
      { 
        id: '164.314', 
        name: 'Organizational Requirements', 
        status: 'Minor Finding',
        details: 'Business Associate Agreements in place, but 2 vendors require updated agreements to reflect recent regulatory changes. Group health plan requirements documented. Business associate contracts include required security provisions but need standardization.'
      },
      { 
        id: '164.316', 
        name: 'Policies and Procedures', 
        status: 'Compliant',
        details: 'Comprehensive policies and procedures implemented and communicated to workforce. Documentation maintained for 6 years as required. Regular reviews and updates of policies conducted. Changes to policies documented with revision history.'
      },
      { 
        id: '164.530', 
        name: 'Privacy Rule Admin Requirements', 
        status: 'Compliant',
        details: 'Privacy officer designated with clear responsibilities. Complaint procedures established and communicated. Mitigation procedures implemented for harmful effects of privacy violations. Retaliation and waiver policies documented and enforced.'
      }
    ]
  }
];

const InfoSecAudits: React.FC = () => {
  const [activeFramework, setActiveFramework] = useState('iso27001');
  const [expandedControl, setExpandedControl] = useState<string | null>(null);
  
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Compliant':
        return 'bg-cyber-success text-white';
      case 'Minor Finding':
        return 'bg-amber-500 text-white';
      case 'Major Finding':
        return 'bg-cyber-danger text-white';
      default:
        return 'bg-cyber-lightgray';
    }
  };

  const toggleControlDetails = (controlId: string) => {
    if (expandedControl === controlId) {
      setExpandedControl(null);
    } else {
      setExpandedControl(controlId);
    }
  };

  return (
      <div className="flex flex-col space-y-4">
        <div className="flex items-center gap-2">
          <FileSearch className="h-6 w-6 text-cyber-accent" />
          <h1 className="text-2xl font-bold">Information Security Audits</h1>
        </div>
        
        <p className="text-cyber-lightgray mb-4">
          Track and manage compliance with key security frameworks and regulations.
        </p>
        
        <Tabs defaultValue={activeFramework} onValueChange={setActiveFramework} className="w-full">
          <TabsList className="mb-4 w-full flex flex-wrap justify-start gap-2 bg-transparent">
            {complianceFrameworks.map((framework) => (
              <TabsTrigger 
                key={framework.id} 
                value={framework.id}
                className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
              >
                <framework.icon className="h-4 w-4 mr-2" />
                {framework.name}
              </TabsTrigger>
            ))}
          </TabsList>
          
          {complianceFrameworks.map((framework) => (
            <TabsContent key={framework.id} value={framework.id} className="space-y-4">
              <Card className="bg-cyber-gray border-cyber-darkgray">
                <CardHeader>
                  <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        <framework.icon className="h-5 w-5 text-cyber-accent" />
                        {framework.name}
                      </CardTitle>
                      <CardDescription className="mt-1">
                        {framework.description}
                      </CardDescription>
                    </div>
                    <Badge className={`text-xs px-2 py-1 ${getStatusColor(framework.status.includes('Compliant') ? 'Compliant' : framework.status)}`}>
                      {framework.status}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div className="bg-cyber-darker p-3 rounded-md">
                      <span className="text-cyber-lightgray text-sm">Last Audit:</span>
                      <p className="font-medium">{new Date(framework.lastAudit).toLocaleDateString()}</p>
                    </div>
                    <div className="bg-cyber-darker p-3 rounded-md">
                      <span className="text-cyber-lightgray text-sm">Next Audit:</span>
                      <p className="font-medium">{new Date(framework.nextAudit).toLocaleDateString()}</p>
                    </div>
                  </div>
                  
                  <div className="mt-4">
                    <h3 className="text-lg font-medium mb-3">Control Requirements</h3>
                    <div className="grid grid-cols-1 gap-3">
                      {framework.controls.map((control) => (
                        <div 
                          key={control.id} 
                          className="bg-cyber-darker p-3 rounded-md transition-all duration-200"
                        >
                          <div 
                            className="flex justify-between items-center cursor-pointer" 
                            onClick={() => toggleControlDetails(`${framework.id}-${control.id}`)}
                          >
                            <div>
                              <span className="text-cyber-accent font-mono">{control.id}</span>
                              <p className="text-sm">{control.name}</p>
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge className={`text-xs ${getStatusColor(control.status)}`}>
                                {control.status}
                              </Badge>
                              {expandedControl === `${framework.id}-${control.id}` ? (
                                <CheckCircle2 className="h-4 w-4 text-cyber-accent" />
                              ) : (
                                <CheckCircle2 className="h-4 w-4 text-cyber-accent opacity-0" />
                              )}
                            </div>
                          </div>
                          
                          {expandedControl === `${framework.id}-${control.id}` && (
                            <div className="mt-3 pt-3 border-t border-cyber-gray">
                              <p className="text-sm text-cyber-lightgray">{control.details}</p>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          ))}
        </Tabs>
      </div>
  );
};

export default InfoSecAudits;
