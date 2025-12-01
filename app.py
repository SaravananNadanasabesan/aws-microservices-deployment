from flask import Flask
import socket

app = Flask(__name__)
hostname = socket.gethostname()
ip_address = socket.gethostbyname(hostname)

# MAIN route – required text for the test
@app.route("/")
def hello_cloud():
    return "Welcome to Nadanasabesan Final Test API Server"

@app.route("/host")
def host_name():
    return hostname

@app.route("/ip")
def host_ip():
    return ip_address

# Keep this only for local testing; gunicorn will be used in the container
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
