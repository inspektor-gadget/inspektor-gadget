import React, {useEffect} from 'react';
import Button from '@mui/material/Button';
import { createDockerDesktopClient } from '@docker/extension-api-client';
import {FormControl, InputLabel, MenuItem, OutlinedInput, Select, Stack, TextField, Typography} from '@mui/material';

// Note: This line relies on Docker Desktop's presence as a host application.
// If you're running this React app in a browser, it won't work properly.
const client = createDockerDesktopClient();

function useDockerDesktopClient() {
  return client;
}

export function App() {
  const [response, setResponse] = React.useState<string>();
  const [gadgetList, setGadgetList] = React.useState<any>();
  const ddClient = useDockerDesktopClient();

  const fetchGadgetCatalog = async () => {
      const gadgetList = await ddClient.extension.vm?.service?.get('/gadgets');
      setGadgetList(gadgetList);
  }

  const fetchAndDisplayResponse = async () => {
    const result = await ddClient.extension.vm?.service?.post('/gadget', {
        id: 'demo',
        gadgetName: 'process',
        gadgetCategory: 'snapshot',
    });
    setResponse(JSON.stringify(result));
  };

  // fetchGadgetCatalog();
    useEffect(() => {
        fetchGadgetCatalog();
    }, [])

    console.log(gadgetList);
  return (
    <>
        <FormControl sx={{ m: 1, width: 300 }}>
            <InputLabel id="gadget-select-label">Name</InputLabel>
            <Select
                title="Gadget"
                labelId="gadget-select-label"
                input={<OutlinedInput label="Gadget" />}>
                {gadgetList?.Gadgets ? gadgetList.Gadgets.map((gadget: any, i: React.Key) => <MenuItem value={`${gadget.category}/${gadget.name}`} key={i} >{gadget.category} / {gadget.name}</MenuItem>) : null}
            </Select>
        </FormControl>
      <Stack direction="row" alignItems="start" spacing={2} sx={{ mt: 4 }}>
        <Button variant="contained" onClick={fetchAndDisplayResponse}>
          Run snapshot process
        </Button>

        <TextField
          label="Backend response"
          sx={{ width: 600, height: 600 }}
          disabled
          multiline
          variant="outlined"
          minRows={5}
          value={response ?? ''}
        />
      </Stack>
    </>
  );
}
