'use strict'
import React from 'react';
import Template from './Conversation.rt.js'

class Conversation extends React.Component{
    
    constructor(props){
        super(props);
    }
    
    render(){
        return Template.call(this);
    }
}

export default Conversation;

