'use strict'
import React from 'react';
import Firebase from '../../firebase';
import Template from './Conversations.rt.js'

class Conversations extends React.Component{
    
    constructor(props){
        super(props);
        this.state = {
            conversations: [],
            loaded: false
        }
    }
    
    componentDidMount(){
        //Sincronizamos el estado con Firebase.
        this.ref = Firebase.syncState('conversations', {
            context: this,
            state: 'conversations', //The state property you want to sync with Firebase
            asArray: true, //Returns the Firebase data at the specified endpoint as an Array instead of an Object
            then: () => {
                this.setState({loaded: true});
            }
        });
    }
    
    componentWillUnmount(){
        Firebase.removeBinding(this.ref);
    }
    
    render(){
        return Template.call(this);
    }
}

export default Conversations;

