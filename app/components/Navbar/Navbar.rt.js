import React from 'react/addons';
import _ from 'lodash';
import Navbar from 'react-bootstrap/lib/Navbar';
import Nav from 'react-bootstrap/lib/Nav';
import NavItem from 'react-bootstrap/lib/NavItem';
import NavDropdown from 'react-bootstrap/lib/NavDropdown';
import MenuItem from 'react-bootstrap/lib/MenuItem';
export default function () {
    return React.createElement(Navbar, { 'inverse': true }, React.createElement(Navbar.Header, {}, React.createElement(Navbar.Brand, {}, React.createElement('a', { 'href': '#' }, 'React-Bootstrap')), React.createElement(Navbar.Toggle, {})), React.createElement(Navbar.Collapse, {}, React.createElement(Nav, {}, React.createElement(NavItem, {
        'eventKey': 1,
        'href': '#'
    }, 'Link'), React.createElement(NavItem, {
        'eventKey': 2,
        'href': '#'
    }, 'Link'), React.createElement(NavDropdown, {
        'eventKey': 3,
        'title': 'Dropdown',
        'id': 'basic-nav-dropdown'
    }, React.createElement(MenuItem, { 'eventKey': 3.1 }, 'Action'), React.createElement(MenuItem, { 'eventKey': 3.2 }, 'Another action'), React.createElement(MenuItem, { 'eventKey': 3.3 }, 'Something else here'), React.createElement(MenuItem, { 'divider': true }), React.createElement(MenuItem, { 'eventKey': 3.3 }, 'Separated link'))), React.createElement(Nav, { 'pullRight': true }, React.createElement(NavItem, {
        'eventKey': 1,
        'href': '#'
    }, 'Link Right'), React.createElement(NavItem, {
        'eventKey': 2,
        'href': '#'
    }, 'Link Right'))));
};