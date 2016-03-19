'use strict'
import React from 'react';
import Template from './Home.rt.js';

class Home extends React.Component{
    
    constructor(props,context){
        super(props,context);
        this.i18n = context.i18n;
    }
    
    render(){
        return Template.call(this);
    }
}

Home.contextTypes = {
    i18n: React.PropTypes.object
};

export default Home;