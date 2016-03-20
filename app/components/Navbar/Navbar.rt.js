import React from 'react/addons';
import _ from 'lodash';
import Navbar from 'react-bootstrap/lib/Navbar';
import Nav from 'react-bootstrap/lib/Nav';
import NavItem from 'react-bootstrap/lib/NavItem';
import NavDropdown from 'react-bootstrap/lib/NavDropdown';
import MenuItem from 'react-bootstrap/lib/MenuItem';
import LinkContainer from 'react-router-bootstrap/lib/LinkContainer';
export default function () {
    return React.createElement(Navbar, { 'inverse': true }, React.createElement(Navbar.Header, {}, React.createElement(Navbar.Brand, {}, React.createElement('a', { 'href': '#' }, 'React-Bootstrap')), React.createElement(Navbar.Toggle, {})), React.createElement(Navbar.Collapse, {}, React.createElement(Nav, {}, React.createElement(LinkContainer, { 'to': { pathname: '/' } }, React.createElement(NavItem, {
        'eventKey': 1,
        'href': '#'
    }, this.i18n.t('navbar.home'))), React.createElement(LinkContainer, { 'to': { pathname: '/conversations' } }, React.createElement(NavItem, {
        'eventKey': 2,
        'href': '#'
    }, this.i18n.t('navbar.conversations')))), React.createElement(Nav, { 'pullRight': true }, React.createElement(NavItem, {
        'eventKey': 1,
        'href': '#'
    }, 'Link Right'), React.createElement(NavItem, {
        'eventKey': 2,
        'href': '#'
    }, 'Link Right'))));
};