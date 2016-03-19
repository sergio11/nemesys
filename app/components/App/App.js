'use strict'
import React from 'react';
import Template from './App.rt.js';

class App extends React.Component{
    
    constructor(props,context){
        super(props,context);
        this.i18n = context.i18n;
    }
    
    render(){
        return Template.call(this);
    }
    
}

App.contextTypes = {
    i18n: React.PropTypes.object
};

export default App;