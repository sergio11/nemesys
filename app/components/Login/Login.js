'use strict'
import React from 'react';
import Firebase from '../../firebase';
import {browserHistory} from 'react-router';
import Template from './Login.rt.js';

class Login extends React.Component{
    
    constructor(props, context){
        super(props);
        this.i18n = context.i18n;
        this.state = {
            email: "",
            password: "",
            authFail: false,
            error: ""
        }
    }
    
    _onSubmit(e){
        e.preventDefault();
        //auth with password
        Firebase.authWithPassword({
            email    : this.state.email,
            password : this.state.password
        },(error, authData) => {
            if (error) {
                this.setState({
                    authFail : true,
                    error: error
                });
                setTimeout(() => {
                    this.setState({
                        authFail : false,
                        error: error
                    });
                },5000);
            } else {
                console.log("Authenticated successfully with payload:", authData);
                //redirect to home
                browserHistory.push('/home');
            }
        });
    }
    
    _authError(error){
        let message;
        switch(error.code){
            case 'INVALID_USER':
            case 'INVALID_PASSWORD':
                message = this.i18n.t("login.errors.user_or_password_invalid");
                break;
        }
        console.log("Error");
        console.log(error.code);
        return message;
    }
    
    _onChange(e){
        let key = e.target.name, value = e.target.value;
        this.state[key] = value;
    }
    
    componentDidMount(){
        $.material.init();
    }

    render(){
        return Template.call(this);
    }
    
}

Login.contextTypes = {
    i18n: React.PropTypes.object
};

export default Login;