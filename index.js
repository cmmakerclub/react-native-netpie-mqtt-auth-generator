'use strict';

var React = require('react-native');
var {
    NativeModules
} = React;

var NETPIE = NativeModules.NetpieAuthModule;

var modules = {
	NETPIE: NETPIE
}

module.exports = modules;
