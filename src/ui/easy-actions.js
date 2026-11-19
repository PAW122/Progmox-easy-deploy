/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* global Ext, Proxmox */
;(function () {
    const maxActions = 12;
    const maxSteps = 20;
    const maxCommandBytes = 8192;
    const maxConfigBytes = 96 * 1024;

    function byteLength(value) {
        return new TextEncoder().encode(value).length;
    }

    function request(url, method, data, success, failure) {
        Proxmox.Utils.API2Request({
            url,
            method,
            jsonData: data,
            success: (response) => success(response.result.data),
            failure: (response) => {
                const result = response.result;
                const message = result && (result.message || result.errors)
                    ? Proxmox.Utils.extractRequestError(result, true)
                    : response.htmlStatus;
                failure(message || 'The request failed.');
            },
        });
    }

    function validateName(value) {
        const name = value.trim();
        if (!name.length || /[\p{Cc}\p{Cf}]/u.test(name)) {
            return 'Enter a name without control or formatting characters.';
        }
        return [...name].length <= 64 || 'Use up to 64 characters.';
    }

    function editRecord(title, fields, apply) {
        const form = Ext.create('Ext.form.Panel', {
            border: false,
            bodyPadding: 12,
            defaults: { anchor: '100%', labelWidth: 120 },
            items: fields,
        });
        const dialog = Ext.create('Ext.window.Window', {
            title,
            modal: true,
            width: Math.min(590, Ext.getBody().getViewSize().width - 24),
            layout: 'fit',
            items: [form],
            buttons: [
                {
                    text: 'Cancel',
                    handler: () => dialog.close(),
                },
                {
                    text: 'Apply',
                    handler: () => {
                        const editor = form.getForm();
                        if (editor.isValid()) {
                            apply(editor.getFieldValues());
                            dialog.close();
                        }
                    },
                },
            ],
        });
        dialog.show();
    }

    function nameField(value, validator = validateName) {
        return {
            xtype: 'textfield',
            name: 'name',
            fieldLabel: 'Name',
            value,
            allowBlank: false,
            validator,
        };
    }

    function editableGrid(layout, title, store, columns, handlers) {
        return Ext.create('Ext.grid.Panel', {
            ...layout,
            title,
            store,
            columns,
            sortableColumns: false,
            tbar: {
                overflowHandler: 'menu',
                items: [
                    { text: 'Add', itemId: 'add', handler: handlers.add },
                    { text: 'Edit', itemId: 'edit', disabled: true, handler: handlers.edit },
                    { text: 'Remove', itemId: 'remove', disabled: true, handler: handlers.remove },
                    '->',
                    { text: 'Up', itemId: 'up', disabled: true, handler: () => handlers.move(-1) },
                    { text: 'Down', itemId: 'down', disabled: true, handler: () => handlers.move(1) },
                ],
            },
            listeners: { itemdblclick: handlers.edit },
        });
    }

    function selectedRecord(grid) {
        return grid.getSelectionModel().getSelection()[0];
    }

    function updateGridButtons(grid, limit, enabled) {
        const store = grid.getStore();
        const record = selectedRecord(grid);
        const index = record ? store.indexOf(record) : -1;

        grid.down('#add').setDisabled(!enabled || store.getCount() >= limit);
        grid.down('#edit').setDisabled(index < 0);
        grid.down('#remove').setDisabled(index < 0);
        grid.down('#up').setDisabled(index < 1);
        grid.down('#down').setDisabled(index < 0 || index >= store.getCount() - 1);
    }

    function moveRecord(grid, offset) {
        const store = grid.getStore();
        const record = selectedRecord(grid);
        const index = record ? store.indexOf(record) + offset : -1;
        if (index >= 0 && index < store.getCount()) {
            store.remove(record);
            store.insert(index, record);
            grid.getSelectionModel().select(record);
        }
    }

    function showConfig(url, guestID, config) {
        const actionStore = Ext.create('Ext.data.Store', {
            autoDestroy: true,
            fields: ['name', 'steps'],
            data: config.actions,
        });
        const stepStore = Ext.create('Ext.data.Store', {
            autoDestroy: true,
            fields: ['name', 'command', 'timeout'],
        });
        const nameColumn = { text: 'Name', dataIndex: 'name', flex: 1, renderer: Ext.String.htmlEncode };
        let dirty = false;
        let saving = false;
        let closing = false;

        function markDirty() {
            dirty = true;
            dialog.down('#save-actions').setDisabled(false);
        }

        function editAction(record) {
            function validateActionName(value) {
                const valid = validateName(value);
                if (valid !== true) {
                    return valid;
                }
                const name = value.trim().toLowerCase();
                if (name === 'config' || name === 'history') {
                    return 'This name is reserved.';
                }
                const duplicate = actionStore.getRange().some((item) =>
                    item !== record && item.get('name').toLowerCase() === name,
                );
                return duplicate ? 'An action with that name already exists.' : true;
            }

            editRecord(record ? 'Edit action' : 'Add action', [
                nameField(record ? record.get('name') : '', validateActionName),
            ], (values) => {
                const name = values.name.trim();
                if (record) {
                    record.set('name', name);
                } else {
                    actions.getSelectionModel().select(actionStore.add({ name, steps: [] })[0]);
                }
                markDirty();
            });
        }

        // The selected action owns its steps. Copy the visible list back after each edit.
        function saveSteps() {
            const action = selectedRecord(actions);
            action.set('steps', stepStore.getRange().map((step) => ({
                name: step.get('name'),
                command: step.get('command'),
                timeout: step.get('timeout'),
            })));
            updateGridButtons(steps, maxSteps, true);
            markDirty();
        }

        function editStep(record) {
            editRecord(record ? 'Edit step' : 'Add step', [
                nameField(record ? record.get('name') : ''),
                {
                    xtype: 'numberfield',
                    name: 'timeout',
                    fieldLabel: 'Timeout (s)',
                    value: record ? record.get('timeout') : 300,
                    minValue: 1,
                    maxValue: 1800,
                    allowDecimals: false,
                    allowBlank: false,
                },
                {
                    xtype: 'textareafield',
                    name: 'command',
                    fieldLabel: 'Bash command',
                    value: record ? record.get('command') : '',
                    height: 200,
                    fieldStyle: 'font-family: monospace',
                    allowBlank: false,
                    validator: (value) => {
                        if (!value.trim().length || value.includes('\u0000')) {
                            return 'Enter a Bash command without null characters.';
                        }
                        return byteLength(value) <= maxCommandBytes || 'The command exceeds 8 KiB.';
                    },
                },
            ], (values) => {
                values.name = values.name.trim();
                if (record) {
                    record.set(values);
                } else {
                    steps.getSelectionModel().select(stepStore.add(values)[0]);
                }
                saveSteps();
            });
        }

        const actions = editableGrid({ region: 'west', width: '42%', split: true }, 'Actions', actionStore, [
            nameColumn,
            { text: 'Steps', width: 66, dataIndex: 'steps', renderer: (value) => value.length },
        ], {
            add: () => editAction(),
            edit: () => editAction(selectedRecord(actions)),
            remove: () => {
                const action = selectedRecord(actions);
                Ext.Msg.confirm('Remove action', `Remove ${Ext.String.htmlEncode(action.get('name'))} and its steps?`, (answer) => {
                    if (answer === 'yes') {
                        actionStore.remove(action);
                        updateGridButtons(actions, maxActions, true);
                        markDirty();
                    }
                });
            },
            move: (offset) => {
                moveRecord(actions, offset);
                markDirty();
            },
        });
        const steps = editableGrid({ region: 'center' }, 'Steps', stepStore, [
            { xtype: 'rownumberer' },
            { ...nameColumn },
            { text: 'Timeout (s)', dataIndex: 'timeout', width: 95 },
        ], {
            add: () => editStep(),
            edit: () => editStep(selectedRecord(steps)),
            remove: () => {
                stepStore.remove(selectedRecord(steps));
                saveSteps();
            },
            move: (offset) => {
                moveRecord(steps, offset);
                saveSteps();
            },
        });

        actions.getSelectionModel().on('selectionchange', (_model, records) => {
            stepStore.loadData(records[0] ? records[0].get('steps') : []);
            updateGridButtons(actions, maxActions, true);
            updateGridButtons(steps, maxSteps, records.length > 0);
        });
        steps.getSelectionModel().on('selectionchange', () => {
            updateGridButtons(steps, maxSteps, !!selectedRecord(actions));
        });

        const viewport = Ext.getBody().getViewSize();
        const hasPreviousActions = config.previousActions?.length > 0;
        const dialog = Ext.create('Ext.window.Window', {
            title: `Actions · Config · Guest ${guestID}`,
            modal: true,
            width: Math.min(840, viewport.width - 24),
            height: Math.min(490, viewport.height - 24),
            layout: 'border',
            defaults: { border: false },
            items: [
                actions,
                steps,
                {
                    xtype: 'component',
                    region: 'south',
                    padding: 10,
                    html: 'Steps run in order as root inside the guest, each in its own Bash process.',
                },
            ],
            listeners: {
                beforeclose: () => {
                    if (saving) {
                        return false;
                    }
                    if (dirty && !closing) {
                        Ext.Msg.confirm('Discard changes', 'Close without saving changes?', (answer) => {
                            if (answer === 'yes') {
                                closing = true;
                                dialog.close();
                            }
                        });
                        return false;
                    }
                    return true;
                },
            },
            buttons: [
                { text: 'Load previous actions', hidden: !hasPreviousActions, handler: loadPreviousActions },
                { text: 'Close', handler: () => dialog.close() },
                { text: 'Save', itemId: 'save-actions', disabled: true, handler: saveConfig },
            ],
        });

        function loadPreviousActions() {
            Ext.Msg.confirm(
                'Load previous actions',
                'The guest configuration changed. Confirm this is the same guest to replace the actions currently in the editor.',
                (answer) => {
                    if (answer === 'yes') {
                        actions.getSelectionModel().deselectAll();
                        actionStore.loadData(config.previousActions);
                        actions.getSelectionModel().select(0);
                        markDirty();
                    }
                },
            );
        }

        function saveConfig() {
            if (saving || !dirty) {
                return;
            }
            const payload = actionStore.getRange().map((action) => ({
                name: action.get('name'),
                steps: action.get('steps'),
            }));
            const emptyAction = payload.find((action) => action.steps.length === 0);
            if (emptyAction) {
                Ext.Msg.alert('Step required', `Add a step to ${Ext.String.htmlEncode(emptyAction.name)}.`);
                return;
            }
            const json = JSON.stringify(payload);
            if (byteLength(json) > maxConfigBytes) {
                Ext.Msg.alert('Configuration too large', 'The configuration exceeds 96 KiB. Move long commands to scripts in the guest.');
                return;
            }

            saving = true;
            dialog.setLoading('Saving actions…');
            request(url, 'PUT', { revision: config.revision, actions: json }, () => {
                saving = false;
                dirty = false;
                dialog.close();
            }, (message) => {
                saving = false;
                dialog.setLoading(false);
                Ext.Msg.alert('Could not save actions', message);
            });
        }

        dialog.show();
        if (actionStore.getCount()) {
            actions.getSelectionModel().select(0);
        }
        updateGridButtons(actions, maxActions, true);
        updateGridButtons(steps, maxSteps, !!selectedRecord(actions));
    }

    function attachActions(panel, type) {
        const guest = panel.pveSelNode.data;
        const toolbar = panel.getDockedItems('toolbar[dock=top]')[0];
        if (Proxmox.UserName !== 'root@pam' || guest.template || !toolbar || toolbar.child('#proxmox-easy-actions')) {
            return;
        }

        const guestID = encodeURIComponent(guest.vmid);
        const url = `/nodes/${encodeURIComponent(guest.node)}/easy-actions/${type}/${guestID}`;
        let currentMenuRequest = 0;
        let loadingConfig = false;
        let starting = false;

        function confirmRun(name, revision) {
            const escapedName = Ext.String.htmlEncode(name);
            Ext.Msg.confirm('Run action', `Run ${escapedName} on guest ${guestID}?`, (answer) => {
                if (answer !== 'yes' || starting) {
                    return;
                }
                starting = true;
                request(`${url}/run`, 'POST', { name, revision }, (upid) => {
                    starting = false;
                    Ext.create('Proxmox.window.TaskViewer', { upid, autoShow: true });
                }, (message) => {
                    starting = false;
                    Ext.Msg.alert('Could not start action', message);
                });
            });
        }

        function openConfig() {
            if (loadingConfig) {
                return;
            }
            loadingConfig = true;
            request(url, 'GET', undefined, (config) => {
                loadingConfig = false;
                if (!panel.destroyed) {
                    showConfig(url, guestID, config);
                }
            }, (message) => {
                loadingConfig = false;
                if (!panel.destroyed) {
                    Ext.Msg.alert('Could not load configuration', message);
                }
            });
        }

        function replaceActions(menu, items) {
            // Keep the Config item mounted while refreshing action names and their revision.
            menu.items.getRange().slice(1).forEach((item) => menu.remove(item, true));
            if (items.length) {
                menu.add('-');
                menu.add(items);
            }
        }

        function loadMenu(menu) {
            const requestID = ++currentMenuRequest;
            replaceActions(menu, [{ text: 'Loading…', disabled: true }]);
            request(url, 'GET', undefined, (config) => {
                if (menu.destroyed || requestID !== currentMenuRequest) {
                    return;
                }
                replaceActions(menu, config.actions.map(({ name }) => ({
                    text: Ext.String.htmlEncode(name),
                    iconCls: 'fa fa-fw fa-play',
                    handler: () => confirmRun(name, config.revision),
                })));
            }, () => {
                if (!menu.destroyed && requestID === currentMenuRequest) {
                    replaceActions(menu, [{ text: 'Could not load actions', disabled: true }]);
                }
            });
        }

        const helpIndex = panel.helpButton ? toolbar.items.indexOf(panel.helpButton) : -1;
        toolbar.insert(helpIndex < 0 ? toolbar.items.getCount() : helpIndex, {
            xtype: 'button',
            itemId: 'proxmox-easy-actions',
            text: 'Actions',
            iconCls: 'fa fa-bolt',
            menu: {
                items: [{ text: 'Config', iconCls: 'fa fa-fw fa-cog', handler: openConfig }],
                listeners: { beforeshow: loadMenu },
            },
        });
    }

    Proxmox.Utils.override_task_descriptions({ easyactions: ['VM/CT', 'Run guest action'] });

    // Both guest panels already construct their normal toolbar in initComponent.
    Ext.define('ProxmoxEasyActions.QemuConfig', {
        override: 'PVE.qemu.Config',
        initComponent: function () {
            this.callParent(arguments);
            attachActions(this, 'qemu');
        },
    });
    Ext.define('ProxmoxEasyActions.LxcConfig', {
        override: 'PVE.lxc.Config',
        initComponent: function () {
            this.callParent(arguments);
            attachActions(this, 'lxc');
        },
    });
})();
