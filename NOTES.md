## Command to execute

`sudo ./webdav > /dev/null 2>&1 &`

## Build

`go build && scp -i ~/github/sharecal/access.pem ~/github/sharecal-webdav/webdav ec2-user@ec2-34-219-27-62.us-west-2.compute.amazonaws.com:/home/ec2-user/sharecal-webdav/webdav`

## Kill

`ps aux | grep webdav`
`sudo kill -9 $PID`
