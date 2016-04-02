'use strict'
import React from 'react';
import Template from './Navbar.rt.js';

class Navbar extends React.Component {
    
    constructor(props,context){
        super(props,context);
        this.i18n = context.i18n;
       
    }
    
    componentDidMount(){
         console.log("Email del usuario: ", this.props);
    }
    
    render(){
        return Template.call(this);
    }
}

Navbar.contextTypes = {
    i18n: React.PropTypes.object
};

export default Navbar;