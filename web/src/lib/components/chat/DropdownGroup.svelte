<script lang="ts">
  import Patterns from "./Patterns.svelte";
  import Models from "./Models.svelte";
  import ModelConfig from "./ModelConfig.svelte";
  import { Select } from "$lib/components/ui/select";
  import { Input } from "$lib/components/ui/input";
  import { Label } from "$lib/components/ui/label";
  import { languageStore } from '$lib/store/language-store';
  import { strategies, selectedStrategy, fetchStrategies } from '$lib/store/strategy-store';
  import { patternVariables } from '$lib/store/pattern-store';
  import { currentSession, setSession } from '$lib/store/chat-store';
  import { sessionAPI, sessions } from '$lib/store/session-store';
  import { onMount } from 'svelte';

  let sessionInput = '';
  let sessionsList: string[] = [];

  // Update sessions list when sessions store changes
  $: if ($sessions) {
    sessionsList = $sessions.map(s => s.Name);
  }

  function handleSessionInput() {
    setSession(sessionInput.trim() || null);
  }

  function handleSessionSelect(event: Event) {
    const target = event.target as HTMLSelectElement;
    const value = target.value;
    sessionInput = value;
    setSession(value || null);
  }

  const languages = [
    { code: '', name: 'Default Language' },
    { code: 'en', name: 'English' },
    { code: 'fr', name: 'French' },
    { code: 'es', name: 'Spanish' },
    { code: 'de', name: 'German' },
    { code: 'zh', name: 'Chinese' },
    { code: 'ja', name: 'Japanese' },
    { code: 'it', name: 'Italian' }
  ];

  let variablesJsonString = '';

  // Parse JSON string and update variables store
  function updateVariables() {
    try {
      if (variablesJsonString.trim() === '') {
        patternVariables.set({});
      } else {
        const parsed = JSON.parse(variablesJsonString);
        if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
          patternVariables.set(parsed);
        }
      }
    } catch (e) {
      // Don't update the store if JSON is invalid - just ignore the error
      // This allows partial typing without breaking
    }
  }

  onMount(() => {
    fetchStrategies();
    sessionAPI.loadSessions();
    sessionInput = $currentSession || '';
  });
</script>

<div class="flex gap-4">
  <!-- Left side - Dropdowns -->
  <div class="w-[35%] flex flex-col gap-3">
    <div>
      <Patterns />
    </div>
    <div>
      <Models />
    </div>
    <div>
      <Select
        bind:value={$languageStore}
        class="bg-primary-800/30 border-none hover:bg-primary-800/40 transition-colors"
      >
        {#each languages as lang}
          <option value={lang.code}>{lang.name}</option>
        {/each}
      </Select>
    </div>
    <div>
      <Select
        bind:value={$selectedStrategy}
        class="bg-primary-800/30 border-none hover:bg-primary-800/40 transition-colors"
      >
        <option value="">None</option>
        {#each $strategies as strategy}
          <option value={strategy.name}>{strategy.name} - {strategy.description}</option>
        {/each}
      </Select>
    </div>
    <div>
      <Label for="session-input" class="text-xs text-white/70 mb-1 block">Session ID</Label>
      <input
        id="session-input"
        type="text"
        bind:value={sessionInput}
        on:blur={handleSessionInput}
        on:keydown={(e) => e.key === 'Enter' && handleSessionInput()}
        placeholder="Enter session name..."
        class="w-full px-3 py-2 text-sm bg-primary-800/30 border-none rounded-md hover:bg-primary-800/40 transition-colors text-white placeholder-white/50 focus:ring-1 focus:ring-white/20 focus:outline-none"
      />
      {#if sessionsList.length > 0}
        <select
          on:change={handleSessionSelect}
          class="w-full mt-2 px-3 py-2 text-sm bg-primary-800/30 border-none rounded-md hover:bg-primary-800/40 transition-colors text-white focus:ring-1 focus:ring-white/20 focus:outline-none"
        >
          <option value="">Load existing session...</option>
          {#each sessionsList as session}
            <option value={session}>{session}</option>
          {/each}
        </select>
      {/if}
    </div>
    <div>
      <Label for="pattern-variables" class="text-xs text-white/70 mb-1 block">Pattern Variables (JSON)</Label>
      <textarea
        id="pattern-variables"
        bind:value={variablesJsonString}
        on:input={updateVariables}
        placeholder="{`{\"lang_code\": \"fr\", \"role\": \"expert\"}`}"
        class="w-full h-20 px-3 py-2 text-sm bg-primary-800/30 border-none rounded-md hover:bg-primary-800/40 transition-colors text-white placeholder-white/50 resize-none focus:ring-1 focus:ring-white/20 focus:outline-none"
        style="font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;"
      ></textarea>
    </div>
  </div>

  <!-- Right side - Model Config -->
  <div class="w-[65%]">
    <ModelConfig />
  </div>
</div>
