'use strict';

const async = require( 'async' );
const AWS = require( 'aws-sdk' );
const awsUtils = require( './aws-utils.js' );
const crypto = require( 'crypto' );
const extend = require( 'extend' );
const jwt = require( 'jsonwebtoken' );
const superagent = require( 'superagent' );
const util = require( 'util' );

let SNSEventEmitter = module.exports = {};

SNSEventEmitter.init = function( options, callback ) {
    const self = this;
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

    self.options = extend( true, {}, options );

    self.listeners = {};
    self.queue = [];

    async.series( [
        // check for config
        function checkConfig( next ) {
            if ( !self.options || !self.options.url || !self.options.secret ) {
                throw new Error( 'Missing Options, current options:\n' + util.inspect( self.options ) );
            }

            next();
        },

        // AWS configuration
        function loadAWSCredentials( next ) {
            AWS.config.correctClockSkew = true; // retry signature expiration errors
            if ( self.options.AWS ) {
                for ( let key in self.options.AWS ) {
                    if ( self.options.AWS.hasOwnProperty( key ) ) {
                        AWS.config[ key ] = self.options.AWS[ key ];
                    }
                }
            }
            next();
        },

        // initialize sns
        function initSNS( next ) {
            self.sns = new AWS.SNS( {
                apiVersion: self.options.AWS && self.options.AWS.SNS ? self.options.AWS.SNS.apiVersion || '2010-03-31' : '2010-03-31'
            } );
            next();
        },

        // create event topic
        function createEventTopic( next ) {
            self.sns.createTopic( {
                Name: self.options.topic || 'sns-events'
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
                Endpoint: self.options.url,
                Protocol: self.options.protocol || 'https',
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
        self._onInitialized();
        self._emit( '__initialized' );
    } );
};

SNSEventEmitter._onInitialized = function() {
    const self = this;

    let event = self.queue.shift();
    while( event ) {
        self.emit( event.eventName, event.event );
        event = self.queue.shift();
    }
};

SNSEventEmitter._verifyMessage = function( request, callback ) {
    const self = this;
    let verified = true;
    let certificate = null;
    let messageString = '';

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
            let error = null;

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
            let verifier = crypto.createVerify( 'RSA-SHA1' );
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
    const self = this;

    // first, respond to SNS that we got the message
    response.send( {
        received: true
    } );

    let messageType = null;
    let handler = null;

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

            const needsConversion = [ 'SubscriptionConfirmation', 'UnsubscribeConfirmation', 'Notification' ].some( function( type ) {
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
            self._emit( 'error', error );
            return;
        }
    } );
};

SNSEventEmitter._onSubscriptionConfirmation = function( request ) {
    const self = this;

    superagent
        .get( request.body.SubscribeURL )
        .accept( 'xml' )
        .parse( awsUtils.parseXMLResponse )
        .end( function( error, _response ) {
            if ( error ) {
                self._emit( 'error', error );
                return;
            }

            if ( typeof _response.body.ConfirmSubscriptionResponse === 'undefined' || typeof _response.body.ConfirmSubscriptionResponse.ConfirmSubscriptionResult === 'undefined' || typeof _response.body.ConfirmSubscriptionResponse.ConfirmSubscriptionResult.SubscriptionArn === 'undefined' ) {
                error = 'Missing subscription ARN in confirmation response!:\n\n ' + _response.text + '\n\n';
                self._emit( 'error', error );
                return;
            }

            self.snsSubscription = _response.body.ConfirmSubscriptionResponse.ConfirmSubscriptionResult.SubscriptionArn;
            self._emit( '__subscribed' );
        } );
};

SNSEventEmitter._onNotification = function( request ) {
    const self = this;

    if ( request.body.Subject !== 'event' ) {
        self._emit( 'error', 'Unknown event subject: ' + request.body.Subject );
        return;
    }

    const token = request.body.Message;
    let decoded = null;

    async.series( [
        // verify and decode webtoken
        function( next ) {
            jwt.verify( token, self.options.secret, function( error, _decoded ) {
                decoded = _decoded;
                next( error );
            } );
        },

        // emit the decoded event
        function( next ) {
            const eventName = decoded.eventName;
            const event = decoded.event;

            self._emit( eventName, event );

            next();
        }
    ], function( error ) {
        if ( error ) {
            self._emit( 'error', error );
        }
    } );
};

SNSEventEmitter._emit = function( eventName, event ) {
    const self = this;
    const listeners = self.listeners[ eventName ];
    if ( listeners && listeners.length > 0 ) {
        listeners.forEach( function( listener ) {
            listener( event );
        } );
    }
};

SNSEventEmitter.emit = function( eventName, event ) {
    const self = this;

    if ( !self.initialized ) {
        self.queue.push( {
            eventName: eventName,
            event: event
        } );
        return;
    }

    let token = null;

    async.series( [
        // create signed token
        function( next ) {
            token = jwt.sign( {
                eventName: eventName,
                event: event
            }, self.options.secret, {
                issuer: self.options.issuer
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
            self._emit( 'error', error );
        }
    } );
};

SNSEventEmitter.addListener = SNSEventEmitter.on = function( eventName, callback ) {
    const self = this;
    self.listeners[ eventName ] = self.listeners[ eventName ] || [];
    self.listeners[ eventName ].push( callback );
};

SNSEventEmitter.removeListener = SNSEventEmitter.off = function( eventName, callback ) {
    const self = this;
    self.listeners[ eventName ] = self.listeners[ eventName ] || [];
    self.listeners[ eventName ] = self.listeners[ eventName ].filter( function( listener ) {
        return listener !== callback;
    } );
};
