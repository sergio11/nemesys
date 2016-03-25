import React from 'react/addons';
import _ from 'lodash';
import {
    ListGroup,
    ListGroupItem,
    Image
} from 'react-bootstrap';
import Loader from 'react-loader';
import Link from 'react-router/lib/Link';
function repeatConversation1(conversation, conversationIndex) {
    return React.createElement(ListGroupItem, { 'key': conversationIndex }, React.createElement('div', { 'className': 'media' }, React.createElement('div', { 'className': 'pull-left' }, React.createElement(Image, {
        'className': 'media-object',
        'src': 'http://lorempixel.com/100/100/people/',
        'circle': true
    })), React.createElement('div', { 'className': 'media-body' }, React.createElement('h4', { 'className': 'media-heading' }, '\r\n                        ', conversation.title, '\r\n                    '), React.createElement('p', {}, ' Tiene ', conversation.messages ? conversation.messages.length : 0, ' mensajes '))));
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