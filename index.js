'use strict';

require( 'es6-shim' ); // shim in the good stuff
var async = require( 'async' );
var AWS = require( 'aws-sdk' );
var awsUtils = require( './aws-utils.js' );
var crypto = require( 'crypto' );
var jwt = require( 'jsonwebtoken' );
var superagent = require( 'superagent' );
var util = require( 'util' );

var SNSEventEmitter = module.exports = {};

SNSEventEmitter.init = function( options, callback ) {
    var self = this;
    callback = callback || function() {};

    if ( self.initialized ) {
        callback();
        return;
    }

    if ( self.initializing ) {
        setTimeout( self._init.bind( self, options, callback ), 100 );
        return;
    }

    self.initializing = true;

    self.listeners = {};

    async.series( [
        // check for config
        function checkConfig( next ) {
            if ( !self.config || !self.config.AWS || !self.config.AWS.accessKeyId || !self.config.AWS.secretAccessKey || !self.config.url || !self.config.secret ) {
                throw new Error( 'Missing configuration.' );
            }

            next();
        },

        // load AWS credentials
        function loadAWSCredentials( next ) {
            AWS.config.region = self.config.AWS.region;
            AWS.config.accessKeyId = self.config.AWS.accessKeyId;
            AWS.config.secretAccessKey = self.config.AWS.secretAccessKey;
            next();
        },

        // initialize sns
        function initSNS( next ) {
            self.sns = new AWS.SNS( {
                apiVersion: self.config.AWS && self.config.AWS.SNS ? self.config.AWS.SNS.apiVersion || '2010-03-31' : '2010-03-31'
            } );
            next();
        },

        // create event topic
        function createEventTopic( next ) {
            self.sns.createTopic( {
                Name: self.config.topic || 'sns-events'
            }, function( error, data ) {
                if ( error ) {
                    next( error );
                    return;
                }

                self.snsTopic = data.TopicArn;
                next();
            } );
        },

        // request subscription
        function requestSubscription( next ) {
            self.sns.subscribe( {
                Endpoint: self.config.url,
                Protocol: self.config.protocol || 'https',
                TopicArn: self.snsTopic
            }, function( error, data ) {
                if ( error ) {
                    next( error );
                    return;
                }

                self.snsSubscription = data.SubscriptionArn;
                next();
            } );
        }
    ], function( error ) {

        self.initializing = false;

        if ( error ) {
            callback( error );
            return;
        }

        self.initialized = true;
        callback();
    } );
};

SNSEventEmitter._verifyMessage = function( request, callback ) {
    var self = this;
    var verified = true;
    var certificate = null;
    var messageString = '';

    async.series( [
        // check signature version
        function checkSignatureVersion( next ) {
            if ( request.body.SignatureVersion !== '1' ) {
                next( {
                    error: 'unsupported signature version',
                    message: 'Unsupported signature version: ' + request.body.SignatureVersion,
                    statusCode: 400
                } );
                return;
            }

            next();
        },

        // get the certificate used to sign the message
        function getCertificateFromCache( next ) {
            self.certificates = self.certificates || {};
            certificate = self.certificates[ request.body.SigningCertURL ];
            next();
        },

        function getCertificate( next ) {
            if ( certificate ) {
                next();
                return;
            }

            superagent
                .get( request.body.SigningCertURL )
                .buffer() // response type is content/unknown, we need to force buffering so it will be read into the response.text
                .end( function( error, response ) {
                    if ( error ) {
                        next( error );
                        return;
                    }

                    certificate = response.text;
                    self.certificates[ request.body.SigningCertURL ] = certificate;
                    next();
                } );
        },

        function constructMessageString( next ) {
            var error = null;

            switch ( request.body.Type ) {
                case 'Notification':
                    [ 'Message', 'MessageId', 'Subject', 'Timestamp', 'TopicArn', 'Type' ].forEach( function( key ) {
                        if ( typeof request.body[ key ] === 'undefined' ) {
                            return;
                        }

                        messageString += key + '\n';
                        messageString += request.body[ key ] + '\n';
                    } );
                    break;

                case 'SubscriptionConfirmation':
                case 'UnsubscribeConfirmation':
                    [ 'Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 'TopicArn', 'Type' ].forEach( function( key ) {
                        if ( typeof request.body[ key ] === 'undefined' ) {
                            return;
                        }

                        messageString += key + '\n';
                        messageString += request.body[ key ] + '\n';
                    } );
                    break;

                default:
                    error = {
                        error: 'unknown message type',
                        message: 'Unknown message type: ' + request.body.Type,
                        statusCode: 400
                    };
            }

            next( error );
        },

        function verifySignature( next ) {
            var verifier = crypto.createVerify( 'RSA-SHA1' );
            verifier.update( messageString, 'utf8' );

            if ( !verifier.verify( certificate, request.body.Signature, 'base64' ) ) {
                next( {
                    error: 'invalid signature',
                    message: 'Invalid message signature.',
                    statusCode: 400
                } );
                return;
            }

            next();
        }
    ], function( error ) {
        callback( error, verified );
    } );
};

SNSEventEmitter.snsMessageHandler = function( request, response ) {
    var self = this;

    // first, respond to SNS that we got the message
    response.send( {
        received: true
    } );

    var messageType = null;
    var handler = null;

    async.series( [
        function getMessageType( next ) {
            messageType = request.headers[ 'x-amz-sns-message-type' ];

            if ( !messageType ) {
                next( {
                    error: 'no message type set',
                    message: 'Could not read message type from x-amz-sns-message-type header.'
                } );
                return;
            }

            next();
        },

        // TODO: remove if AWS fixes their shit: https://forums.aws.amazon.com/message.jspa?messageID=418160
        function fixMessageBody( next ) {
            if ( request.headers[ 'content-type' ].indexOf( 'text/plain' ) !== 0 ) {
                next();
                return;
            }

            var needsConversion = [ 'SubscriptionConfirmation', 'UnsubscribeConfirmation', 'Notification' ].some( function( type ) {
                return request.headers[ 'x-amz-sns-message-type' ] === type;
            } );

            if ( !needsConversion ) {
                next();
                return;
            }

            try {
                request.body = JSON.parse( request.body );
            }
            catch ( ex ) {
                next( ex );
                return;
            }

            next();
        },

        function verifyMessage( next ) {
            self._verifyMessage( request, function( error, verified ) {
                if ( error ) {
                    next( error );
                    return;
                }

                if ( !verified ) {
                    next( {
                        error: 'invalid message',
                        message: 'Could not verify message.'
                    } );
                    return;
                }

                next();
            } );
        },

        function getHandler( next ) {
            handler = self[ '_on' + messageType ];
            if ( !handler ) {
                next( {
                    error: 'unsupported message type',
                    message: 'No handler for message type: ' + messageType
                } );
                return;
            }

            next();
        },

        function executeHandler( next ) {
            handler.call( self, request, response, next );
        }

    ], function( error ) {
        if ( error ) {
            console.error( util.inspect( error ) );
            return;
        }
    } );
};

SNSEventEmitter._onSubscriptionConfirmation = function( request ) {
    var self = this;

    superagent
        .get( request.body.SubscribeURL )
        .accept( 'xml' )
        .parse( awsUtils.parseXMLResponse )
        .end( function( error, _response ) {
            if ( error ) {
                console.error( error );
                return;
            }

            if ( typeof _response.body.ConfirmSubscriptionResponse === 'undefined' || typeof _response.body.ConfirmSubscriptionResponse.ConfirmSubscriptionResult === 'undefined' || typeof _response.body.ConfirmSubscriptionResponse.ConfirmSubscriptionResult.SubscriptionArn === 'undefined' ) {
                console.error( 'Missing subscription ARN in confirmation response!:\n\n ' + _response.text + '\n\n' );
                return;
            }

            self.snsSubscription = _response.body.ConfirmSubscriptionResponse.ConfirmSubscriptionResult.SubscriptionArn;
        } );
};

SNSEventEmitter._onNotification = function( request ) {
    var self = this;

    if ( request.body.Subject !== 'event' ) {
        console.error( 'Unknown event subject: ' + request.body.Subject );
        return;
    }

    var token = request.body.Message;
    var decoded = null;

    async.series( [
        // verify and decode webtoken
        function( next ) {
            jwt.verify( token, self.config.secret, function( error, _decoded ) {
                decoded = _decoded;
                next( error );
            } );
        },

        // emit the decoded event
        function( next ) {
            var eventName = decoded.eventName;
            var event = decoded.event;

            var listeners = self.listeners[ eventName ];
            if ( listeners && listeners.length > 0 ) {
                listeners.forEach( function( listener ) {
                    listener( event );
                } );
            }

            next();
        }
    ], function( error ) {
        if ( error ) {
            console.error( error );
        }
    } );
};

SNSEventEmitter.emit = function( eventName, event ) {
    var self = this;

    var token = null;

    async.series( [
        // create signed token
        function( next ) {
            token = jwt.sign( {
                eventName: eventName,
                event: event
            }, self.config.secret, {
                issuer: self.config.issuer
            } );
            next();
        },

        // post message
        function( next ) {
            self.sns.publish( {
                Subject: 'event',
                Message: token,
                TopicArn: self.snsTopic
            }, next );
        }
    ], function( error ) {
        if ( error ) {
            console.error( util.inspect( error ) );
        }
    } );
};

SNSEventEmitter.addListener = SNSEventEmitter.on = function( eventName, callback ) {
    var self = this;
    self.listeners[ eventName ] = self.listeners[ eventName ] || [];
    self.listeners[ eventName ].push( callback );
};

SNSEventEmitter.removeListener = SNSEventEmitter.off = function( eventName, callback ) {
    var self = this;
    self.listeners[ eventName ] = self.listeners[ eventName ] || [];
    self.listeners[ eventName ] = self.listeners.filter( function( listener ) {
        return listener !== callback;
    } );
};
