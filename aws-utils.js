'use strict';

const xml2js = require( 'xml2js' );

let AWSUtils = module.exports = {};

AWSUtils.parseXMLResponse = function parseXMLResponse( response, callback ) {
    response.text = '';
    response.setEncoding( 'utf8' );

    response.on( 'data', function( chunk ) {
        response.text += chunk;
    } );

    response.on( 'end', function() {
        try {
            xml2js.parseString( response.text, {
                explicitArray: false
            }, callback );
        } catch ( ex ) {
            callback( ex );
        }
    });
};
