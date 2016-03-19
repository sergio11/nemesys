import React from 'react/addons';
import _ from 'lodash';
import Navbar from '../Navbar/Navbar';
export default function () {
    return React.createElement('div', {}, React.createElement(Navbar, {}), React.createElement('main', { 'className': 'main' }, '\r\n        ', this.props.children, '\r\n    '));
};