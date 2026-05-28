import React, { useState } from 'react';
import { Button, Modal, Select, Input, Form, Typography, Tag, Space, notification } from 'antd';
import { KeyOutlined } from '@ant-design/icons';
import { getAssistantConfig, setAssistantConfig, clearAssistantConfig } from '../utils/assistantKey';

const MODEL_PLACEHOLDER = {
  openai: 'gpt-4o-mini (default)',
  anthropic: 'claude-haiku-4-5 (default)',
};

export default function AssistantSettings() {
  const [open, setOpen] = useState(false);
  const cfg = getAssistantConfig();
  const [provider, setProvider] = useState(cfg?.provider || 'openai');
  const [apiKey, setApiKey] = useState(cfg?.apiKey || '');
  const [model, setModel] = useState(cfg?.model || '');
  const configured = !!cfg?.apiKey;

  const onSave = () => {
    if (!apiKey.trim()) {
      notification.warning({ message: 'No key entered', description: 'Enter an API key, or click "Clear key" to use the server default.', placement: 'topRight' });
      return;
    }
    setAssistantConfig({ provider, apiKey: apiKey.trim(), model: model.trim() });
    notification.success({ message: 'Assistant key saved', description: `Stored in this browser tab (${provider}).`, placement: 'topRight' });
    setOpen(false);
  };

  const onClear = () => {
    clearAssistantConfig();
    setApiKey(''); setModel('');
    notification.success({ message: 'Assistant key cleared from this tab', placement: 'topRight' });
    setOpen(false);
  };

  return (
    <>
      <Button size="small" icon={<KeyOutlined />} onClick={() => setOpen(true)}>
        Assistant key {configured && <Tag color="green" style={{ marginLeft: 6 }}>{cfg.provider}</Tag>}
      </Button>
      <Modal
        title="Assistant API key"
        open={open}
        onOk={onSave}
        okText="Save"
        onCancel={() => setOpen(false)}
        footer={[
          configured && <Button key="clear" danger onClick={onClear}>Clear key</Button>,
          <Button key="cancel" onClick={() => setOpen(false)}>Cancel</Button>,
          <Button key="save" type="primary" onClick={onSave}>Save</Button>,
        ]}
      >
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          Use your own provider key for "Ask Assistant".
        </Typography.Paragraph>
        <Form layout="vertical">
          <Form.Item label="Provider">
            <Select
              value={provider}
              onChange={setProvider}
              options={[{ value: 'openai', label: 'OpenAI' }, { value: 'anthropic', label: 'Anthropic (Claude)' }]}
            />
          </Form.Item>
          <Form.Item label="API key">
            <Input.Password
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={provider === 'anthropic' ? 'sk-ant-...' : 'sk-...'}
              allowClear
            />
          </Form.Item>
          <Form.Item label="Model (optional)">
            <Input value={model} onChange={(e) => setModel(e.target.value)} placeholder={MODEL_PLACEHOLDER[provider]} allowClear />
          </Form.Item>
        </Form>
        <Space size={4}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            Note: flow/XAI data is sent to the selected provider to generate the explanation.
          </Typography.Text>
        </Space>
      </Modal>
    </>
  );
}
