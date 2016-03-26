'use strict'
import React from 'react';
import {browserHistory} from 'react-router';
import Template from './App.rt.js';
import Firebase from '../../firebase';

class App extends React.Component{
    
    constructor(props,context){
        super(props,context);
        this.i18n = context.i18n;
    }
    
    _onAuthCallback(authData){
        console.log("Auth Data");
        console.log(authData);
    }
    
    componentDidMount(){
        let authData = Firebase.getAuth();
        //browserHistory.push();
        console.log(authData);
        //listen to auth user change
        Firebase.onAuth(this._onAuthCallback);
    }
    
    render(){
        return Template.call(this);
    }
    
}

App.contextTypes = {
    i18n: React.PropTypes.object
};

export default App;