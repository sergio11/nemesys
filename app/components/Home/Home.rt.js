import React from 'react/addons';
import _ from 'lodash';
import Jumbotron from 'react-bootstrap/lib/Jumbotron';
import Button from 'react-bootstrap/lib/Button';
import Conversations from '../conversations/Conversations';
export default function () {
    return React.createElement(Jumbotron, {}, React.createElement('h1', {}, 'Hello,  cracks !!!'), React.createElement('p', {}, 'This is a simple hero unit, a simple jumbotron-style component for calling extra attention to featured content or information.'), React.createElement('p', {}, React.createElement(Button, { 'bsStyle': 'primary' }, 'Learn more')));
};