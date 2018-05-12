package azuresecrets

type azureClient struct {
	settings *azureSettings
	provider Provider
}

func (b *azureSecretBackend) newAzureClient() (*azureClient, error) {
	settings, err := getAzureSettings(&azureConfig{})

	if err != nil {
		return nil, err
	}

	p, err := b.getProvider()
	if err != nil {
		return nil, err
	}

	c := azureClient{
		settings: settings,
		provider: p,
	}

	return &c, nil
}
