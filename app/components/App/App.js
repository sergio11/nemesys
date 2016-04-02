'use strict'
import React from 'react';
import {browserHistory} from 'react-router';
import Template from './App.rt.js';
import Firebase from '../../firebase';

class App extends React.Component{
    
    constructor(props,context){
        super(props,context);
        this.i18n = context.i18n;
        this.state = {
            auth_data: null
        }
    }
    
    _onAuthCallback(authData){
        this.setState({auth_data: authData});
    }
    
    componentDidMount(){
        let authData = Firebase.getAuth();
        //browserHistory.push();
        console.log(authData);
        //listen to auth user change
        Firebase.onAuth(this._onAuthCallback.bind(this));
    }
    
    render(){
        return Template.call(this);
    }
    
}

App.contextTypes = {
    i18n: React.PropTypes.object
};

export default App;