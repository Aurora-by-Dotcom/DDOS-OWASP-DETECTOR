# DDOS-OWASP-DETECTOR
DDOS OWASP DETECTOR 

Installation Guide

Install Go if not installed : v1.23.0

    sudo rm -rf /usr/local/go

    wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz

    sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz

    export PATH=$PATH:/usr/local/go/bin

    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc

    source ~/.bashrc

    go version

Install dependancy tail : 

    go get github.com/hpcloud/tail@latest

    go mod tidy

Vérifier la configuration de Nginx : Assurer que Nginx enregistre les logs au format combiné dans /var/log/nginx/access.log : 

      sudo apt install nginx -yy
      
      sudo systemctl start nginx
      
      sudo systemctl enable nginx
      
    sudo systemctl status nginx

Install iptables if necessairey : 

    sudo apt update

    sudo apt install iptables

Enregistrer le code : Placez le code main.go dans le répertoire ~/ddos-detector : 

    mkdir -p ~/ddos-detector

    nano ~/ddos-detector/main.go

Compile and execute the program: (execute with sudo to allow iptables modifications ) : 

    cd ~/ddos-detector

    sudo /usr/local/go/bin/go run main.go

