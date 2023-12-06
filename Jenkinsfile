pipeline {
    agent any

    environment {
        VENV_PATH = "/var/lib/jenkins/workspace/cve-exclusions/venv"
    }

    parameters {
        string(name: 'CVE_LIST_NAME', defaultValue: 'DAMNLIST', description: 'The name of the CVE list')
        string(name: 'IMAGE_NAME', defaultValue: 'nginx:latest', description: 'The name of the image to search for CVEs')
        string(name: 'AUTH_TOKEN', defaultValue: '', description: 'Basic Authorization token for API calls')
    }

    stages {
        stage('Setup Virtual Environment') {
            steps {
                sh """
                #!/bin/bash
                # Create the virtual environment if it does not exist
                if [ ! -d "${VENV_PATH}" ]; then
                    /usr/bin/env python3 -m venv "${VENV_PATH}"
                fi

                # Activate the virtual environment
                . "${VENV_PATH}/bin/activate"

                # Upgrade pip and install required Python modules
                pip install --upgrade pip
                pip install pandas requests openpyxl
                """
            }
        }

        stage('Run CVE Script') {
            steps {
                // Using 'withEnv' to export parameters as environment variables
                withEnv([
                    "CVE_LIST_NAME=${params.CVE_LIST_NAME}",
                    "IMAGE_NAME=${params.IMAGE_NAME}",
                    "AUTH_TOKEN=${params.AUTH_TOKEN}"
                ]) {
                    sh """
                    #!/bin/bash
                    # Activate the virtual environment before executing our Python script
                    . "${VENV_PATH}/bin/activate"
                    # Run the script. Assuming 'jenkinsjob.py' is in the current working directory
                    python3 jenkinsjob.py
                    """
                }
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}
