## Instruction

[here]: <https://hub.docker.com/_/golang/>

Use the dockerfile to test the go script.
You'll find further details on how to use the docker-image [here]

Build the image with this command

```sh
sudo docker build -t my-golang-app .
```

Run the container with this command

```sh
sudo docker run -it --rm -p 8000:8000 --name my-running-app my-golang-app
```

The APIs will be accessible via **http://<server-ip>:8000**
For the API calls, chekc the *main.go* file