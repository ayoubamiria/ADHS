pipeline {
    agent any

    triggers {
        githubPush() // Le pipeline se déclenche automatiquement à chaque push
    }

    environment {
        ANSIBLE_FORCE_COLOR = 'true'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Run Ansible Playbook') {
            steps {
                withCredentials([string(credentialsId: 'docker_password', variable: 'DOCKER_PASSWORD')]) {
                    sh '''
                        ansible-playbook -i inventory.ini playbook.yml \
                        --extra-vars "docker_password=${DOCKER_PASSWORD}"
                    '''
                }
            }
        }
    }

    post {
        success {
            echo '✅ Le pipeline s’est terminé avec succès.'
        }
        failure {
            echo '❌ Le pipeline a échoué. Vérifiez les logs.'
        }
        always {
            echo 'ℹ️ Fin du pipeline (succès ou échec).'
        }
    }
}
