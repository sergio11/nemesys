'use strict'
import React from 'react';
import {browserHistory} from 'react-router';
import Firebase from '../../firebase';
import Template from './SignUp.rt.js';

class SignUp extends React.Component{
    
    constructor(props, context){
        super(props);
        this.i18n = context.i18n;
        this.state = {
            firstname: "",
            lastname: "",
            birthday: new Date().toISOString(),
            email: "",
            password: ""
        }
    }
    
    _saveUserInfo(data){
        
        Firebase.push('users', {
            data: {
                firstname: this.state.firstname,
                lastname: this.state.lastname,
                birthday: this.state.birthday,
                uid: data.uid
            },
            then: () => {
                
                Firebase.authWithPassword({
                    email: this.state.email,
                    password: this.state.password
                }, (error, authData) => {
                    if (!error) {
                        browserHistory.push('/home');
                    }
                });
            }
        });
        
    }
    
    _createUser(e){
        e.preventDefault();
        Firebase.createUser({
            email: this.state.email,
            password: this.state.password
        },(error, authData) => {
            if(error){
                console.log("Error : ", error);
            }else{
               this._saveUserInfo(authData);
            }
        });
    }
    
    _onChange(e){
        let key = e.target.name, value = e.target.value;
        this.state[key] = value;
    }
    
    _onChageDatePicker(date){
        this.setState({'birthday': date});
    }
    
    componentDidMount(){
        $.material.init();
    }
    
    render(){
        return Template.call(this);
    }
}

SignUp.contextTypes = {
    i18n: React.PropTypes.object
};

export default SignUp;