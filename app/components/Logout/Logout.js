'use strict';
import React from 'react';
import Firebase from '../../firebase';
import Template from './Logout.rt.js';

class Logout extends React.Component{
    
    constructor(props, context){
        super(props, context)
        this.i18n = context.i18n;
        console.log("Las props del Logout : ", props);
    }
    
    componentDidMount(){
        console.log("Cerrando Sesión ....");
        Firebase.unauth();
    }
    
    render(){
        return Template.call(this);
    }
    
}

export default Logout;