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
            user: null
        }
    }
    
    _onAuthCallback(authData){
        if(authData){
            Firebase.fetch('users', {
                context: this,
                asArray: true,
                queries: {
                    orderByChild: 'uid',
                    equalTo: authData.uid
                },
                then: (user) => {
                    this.setState({user: user ? user[0] : null});
                }
            });
        }else{
            this.setState({user: null});
        }
        
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