# Primer [![Travis build status](https://travis-ci.org/phaneesh/primer.svg?branch=master)](https://travis-ci.org/phaneesh/primer)

Primer is a low latency high throughput [JWT](https://jwt.io) service which can be used to secure API interactions. 
Primer is built with dropwizard and uses hystrix for fault tolerance & isolation.
Primer is build on Java 8 & compiles only on Java 8
 
## Dependencies
* dropwizard
* Hystrix
* Aerospike

## Usage
This service can be used as the token store which can be used to verify and validate the claims by api client.
More about JWT [here](https://jwt.io/)   

### Build instructions
  - Clone the source:

        git clone github.com/phaneesh/primer

  - Build

        mvn package
  - Run
        docker-compose up

## API Documentation
The service has swagger documentation can can be used to try and check api definitions at <host>:8080/swagger

LICENSE
-------

Copyright 2016 Phaneesh Nagaraja <phaneesh.n@gmail.com>.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.