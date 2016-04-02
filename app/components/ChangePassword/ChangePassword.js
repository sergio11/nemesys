'use strict';
import React from 'react';
import Firebase from '../../firebase';
import Template from './ChangePassword.rt.js';

class ChangePassword extends React.Component {
    
    constructor(props, context){
        super(props,context);
        this.i18n = context.i18n;
        this.state = {
            email: "",
            oldPassword: "",
            newPassword: "",
            status: "pristine"
        }
    }
    
    _onSubmit(e){
        e.preventDefault();
        console.log("Este es el Estado : ", this.state);
        Firebase.changePassword({
            email: this.state.email,
            oldPassword: this.state.oldPassword,
            newPassword: this.state.newPassword
        }, (error) => {
            if(!error){
                this.setState({status: "changed"});
            }else{
                this.setState({status: "nochanged"});
            }
        });
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

ChangePassword.contextTypes = {
    i18n: React.PropTypes.object
};

export default ChangePassword;