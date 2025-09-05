// Jenkins Pipeline for Threat Feed Security Check
// This pipeline runs the threat feed action to check for vulnerable packages

pipeline {
    agent any
    
    environment {
        // Set these in Jenkins > Manage Jenkins > Configure System > Global Properties
        // or in your pipeline configuration
        PHYLUM_API_TOKEN = credentials('phylum-api-token')
        VERACODE_API_ID = credentials('veracode-api-id')
        VERACODE_API_KEY = credentials('veracode-api-key')
        DEBUG = 'true'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Setup') {
            steps {
                script {
                    sh '''
                        git clone https://github.com/your-username/threat-feed-action.git action
                        cd action
                    '''
                }
            }
        }
        
        stage('Security Check') {
            steps {
                script {
                    sh '''
                        cd action
                        node dist/index.js
                    '''
                }
            }
        }
    }
    
    post {
        always {
            // Archive security reports
            archiveArtifacts artifacts: 'action/summary.txt, action/new-malicious-packages.txt', 
                           fingerprint: true,
                           allowEmptyArchive: true
            
            // Publish test results
            publishTestResults testResultsPattern: 'action/summary.txt',
                              allowEmptyResults: true,
                              failIfNoResults: false
        }
        
        failure {
            echo 'Security check failed - vulnerable packages found!'
            // You can add notifications here (email, Slack, etc.)
        }
        
        success {
            echo 'Security check passed - no vulnerable packages found!'
        }
    }
}
