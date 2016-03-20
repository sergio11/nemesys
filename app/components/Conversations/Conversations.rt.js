import React from 'react/addons';
import _ from 'lodash';
import ListGroup from 'react-bootstrap/lib/ListGroup';
import ListGroupItem from 'react-bootstrap/lib/ListGroupItem';
import Loader from 'react-loader';
function repeatConversation1(conversation, conversationIndex) {
    return React.createElement(ListGroupItem, {
        'key': conversationIndex,
        'header': conversation.title
    }, 'Tiene ', conversation.messages ? conversation.messages.length : 0, ' mensajes ');
}
export default function () {
    return React.createElement(Loader, {
        'loaded': this.state.loaded,
        'color': '#bf5a16',
        'top': '50%',
        'left': '50%',
        'scale': 1,
        'width': 10
    }, React.createElement.apply(this, [
        ListGroup,
        {},
        _.map(this.state.conversations, repeatConversation1.bind(this))
    ]));
};