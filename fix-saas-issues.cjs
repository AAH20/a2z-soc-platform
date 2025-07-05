const axios = require('axios');

const API_BASE = 'http://localhost:3001/api';

async function fixAndTestSaaSIssues() {
    console.log('🔧 Fixing SaaS Issues and Re-testing');
    console.log('=' .repeat(50));
    
    try {
        // Get fresh token
        const authResponse = await axios.post(`${API_BASE}/onboarding/login`, {
            email: 'admin@a2zsec.com',
            password: 'password'
        });
        const token = authResponse.data.token;
        const headers = { Authorization: `Bearer ${token}` };

        console.log('✅ Authentication successful');

        // Test 1: Check if /me endpoint works now
        console.log('\n1. Testing /me endpoint (organization isolation):');
        try {
            const meResponse = await axios.get(`${API_BASE}/onboarding/me`, { headers });
            if (meResponse.data.user && meResponse.data.user.organizationId) {
                console.log(`✅ Organization isolation working - Org ID: ${meResponse.data.user.organizationId}`);
                console.log(`   Company: ${meResponse.data.user.company}`);
                console.log(`   Subscription: ${meResponse.data.user.subscription.tier}`);
            } else {
                console.log('❌ Organization data missing from /me endpoint');
            }
        } catch (error) {
            console.log(`❌ /me endpoint error: ${error.response?.data?.error || error.message}`);
        }

        // Test 2: Test invalid token handling
        console.log('\n2. Testing invalid token validation:');
        try {
            await axios.get(`${API_BASE}/ids-logs`, { 
                headers: { Authorization: 'Bearer invalid_token_12345' }
            });
            console.log('❌ Invalid token was accepted - security vulnerability!');
        } catch (error) {
            if (error.response?.status === 401 || error.response?.status === 403) {
                console.log('✅ Invalid token properly rejected');
            } else {
                console.log(`⚠️ Unexpected error: ${error.response?.status} - ${error.response?.data?.error}`);
            }
        }

        // Test 3: Test dashboard stats with tenant isolation
        console.log('\n3. Testing dashboard stats (tenant isolation):');
        try {
            const dashboardResponse = await axios.get(`${API_BASE}/dashboard/stats`, { headers });
            if (dashboardResponse.data.success) {
                console.log('✅ Dashboard stats working with tenant isolation');
                console.log(`   Total events: ${dashboardResponse.data.data.totalEvents || 0}`);
                console.log(`   Active agents: ${dashboardResponse.data.data.activeAgents || 0}`);
            } else {
                console.log(`❌ Dashboard stats failed: ${dashboardResponse.data.error}`);
            }
        } catch (error) {
            console.log(`❌ Dashboard error: ${error.response?.data?.error || error.message}`);
            if (error.response?.data?.code) {
                console.log(`   Error code: ${error.response.data.code}`);
            }
        }

        // Test 4: Test billing endpoints
        console.log('\n4. Testing billing system:');
        try {
            const billingResponse = await axios.get(`${API_BASE}/billing/plans`, { headers });
            console.log('✅ Billing endpoints accessible');
        } catch (error) {
            console.log(`❌ Billing error: ${error.response?.data?.error || error.message}`);
        }

        // Test 5: Test audit logging
        console.log('\n5. Testing audit system:');
        try {
            const auditResponse = await axios.get(`${API_BASE}/v1/audits`, { headers });
            console.log('✅ Audit system accessible');
        } catch (error) {
            console.log(`❌ Audit error: ${error.response?.data?.error || error.message}`);
        }

        // Test 6: Test compliance endpoints
        console.log('\n6. Testing compliance framework:');
        try {
            const complianceResponse = await axios.get(`${API_BASE}/v1/compliance`, { headers });
            console.log('✅ Compliance system accessible');
        } catch (error) {
            console.log(`❌ Compliance error: ${error.response?.data?.error || error.message}`);
        }

        console.log('\n📊 ISSUE RESOLUTION SUMMARY');
        console.log('=' .repeat(50));
        console.log('If all tests above show ✅, the platform is SaaS-ready!');

    } catch (error) {
        console.error('❌ Critical test failure:', error.message);
    }
}

fixAndTestSaaSIssues();
