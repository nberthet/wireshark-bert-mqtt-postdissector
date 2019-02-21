BERT (Binary ERlang Term) post dissector to parse BERT-encoded MQTT messages

Installation
============

Place the .lua file in WireShark's `./plugins/`; it will be loaded at startup.
Alternatively, past the file content in the _Lua Evaluate_ window (Tools > Lua > Evaluate)
and evaluate it.

Usage
=====

The plugin is a post dissector, meanining it will automatically process packets after 
dissectors and parse the content of MQTT packets. 
